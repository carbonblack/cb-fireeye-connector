import os
import sys
import time
import flask
import socket
import logging

import cbfireeyebridge.version
import cbapi
import cbint.utils.json
import cbint.utils.feed
import cbint.utils.flaskfeed
import cbint.utils.filesystem
import cbint.utils.cbserver
from cbint.utils.detonation import FeedSyncRunner
from cbint.utils.daemon import CbIntegrationDaemon
import copy
import re

logger = logging.getLogger(__name__)

digit_re = re.compile("(\d+)")


class FeedReportBase(object):
    def __init__(self, feed_metadata):
        self.feed_metadata = feed_metadata

    def add_report(self, report):
        pass

    def retrieve_feed(self):
        pass


class SimpleFeedReport(FeedReportBase):
    def __init__(self, feed_metadata):
        super(SimpleFeedReport, self).__init__(feed_metadata)
        self.data = []

    def add_report(self, report):
        self.data.append(report)

    def retrieve_feed(self):
        retval = copy.deepcopy(self.feed_metadata)
        retval["reports"] = self.data[:]
        return retval


class DedupFeedIOCReports(FeedReportBase):
    def __init__(self, feed_metadata):
        super(DedupFeedIOCReports, self).__init__(feed_metadata)
        self.data = {}

    def add_report(self, report):
        if len(report.get("iocs", {})) == 0:
            return

        # the de-duplication key is the report title concatenated with the IOCs for the report
        report_key = report.get("title", "no_title")
        iocs = report.get("iocs", {})
        key = {}
        for k, v in iocs.iteritems():
            key[k] = ','.join(v)
        key = report_key + '|' + '|'.join(["%s:%s" % (k, v) for k, v in key.iteritems()])

        if key not in self.data:
            self.data[key] = report

    def retrieve_feed(self):
        retval = copy.deepcopy(self.feed_metadata)
        retval["reports"] = [v for v in self.data.itervalues()]
        return retval


class CarbonBlackFireEyeBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile, **kwargs):
        if 'data_dir' in kwargs:
            self.data_dir = kwargs.pop('data_dir')
        else:
            self.data_dir = "/usr/share/cb/integrations/fireeye/received_alerts"

        CbIntegrationDaemon.__init__(self, name, configfile=configfile, **kwargs)
        self.flask_feed = cbint.utils.flaskfeed.FlaskFeed(__name__)
        self.bridge_options = {}
        self.debug = False
        self.feed_name = "FireEye"
        self.display_name = self.feed_name

        self.feed_synchronizer = None
        self.directory = "/usr/share/cb/integrations/fireeye"
        self.cb_image_path = "/carbonblack.png"
        self.integration_image_path = "/fireeye.png"
        self.json_feed_path = "/fireeye/json"

        feed_metadata = cbint.utils.feed.generate_feed(self.feed_name, summary="FireEye on-premise IOC feed",
                                                       tech_data="There are no requirements to share any data with Carbon Black to use this feed.  The underlying IOC data is provided by an on-premise FireEye device",
                                                       provider_url="http://www.fireeye.com/",
                                                       icon_path="%s/%s" % (self.directory,
                                                                            self.integration_image_path),
                                                       display_name=self.display_name, category="Connectors")

        self.feed = DedupFeedIOCReports(feed_metadata)

        self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/fireeye/alert", view_func=self.handle_posted_alert, methods=['POST'])

        self.alert_processing_failures = []
        self.score_stats = {}

    def on_start(self):
        self.debug = self.bridge_options.get('debug', "0") != "0"
        if self.debug:
            logger.setLevel(logging.DEBUG)

    def on_stopping(self):
        self.debug = self.bridge_options.get('debug', "0") != "0"
        if self.debug:
            logger.setLevel(logging.DEBUG)

    def run(self):
        self.debug = self.bridge_options.get('debug', "0") != "0"
        if self.debug:
            logger.setLevel(logging.DEBUG)

        logger.info("starting Carbon Black <-> FireEye Bridge | version %s" % cbfireeyebridge.version.__version__)

        logger.debug("initializing cbapi")
        sslverify = False if self.bridge_options.get('carbonblack_server_sslverify', "0") == "0" else True
        self.cb = cbapi.CbApi(self.bridge_options['carbonblack_server_url'],
                              token=self.bridge_options['carbonblack_server_token'],
                              ssl_verify=sslverify)

        logger.debug("starting feed synchronizer")
        feed_url = "http://%s:%d%s" % (self.bridge_options["feed_host"], int(self.bridge_options["listener_port"]),
                                       self.json_feed_path)

        self.feed_synchronizer = FeedSyncRunner(self.cb, self.feed_name, feed_url,
                                                interval=self.bridge_options.get('feed_sync_interval', 1))
        if not self.feed_synchronizer.sync_supported:
            logger.warn("feed synchronization is not supported by the associated Carbon Black enterprise server")

        # make data directories as required
        #
        cbint.utils.filesystem.ensure_directory_exists(self.data_dir)
        cbint.utils.filesystem.ensure_directory_exists('%s/valid' % self.data_dir)
        cbint.utils.filesystem.ensure_directory_exists('%s/invalid' % self.data_dir)

        # restore alerts from disk if so configured
        #
        if int(self.bridge_options.get('restore_alerts_on_restart', 0)):
            logger.info("Restoring saved alerts...")
            num_restored = self.restore_alerts()
            if num_restored > 0:
                self.feed_synchronizer.sync_needed = True
            logger.info("Restored %d alerts from %d on-disk files" % (len(self.feed.retrieve_feed()['reports']),
                                                                      num_restored))

        logger.debug("starting flask")
        self.serve()

    def serve(self):
        address = self.bridge_options.get('listener_address', '0.0.0.0')
        port = self.bridge_options['listener_port']
        logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=self.debug,
                                host=address, use_reloader=False)

    def handle_json_feed_request(self):
        return self.flask_feed.generate_json_feed(self.feed.retrieve_feed())

    def handle_html_feed_request(self):
        return self.flask_feed.generate_html_feed(self.feed.retrieve_feed(), self.display_name)

    def handle_index_request(self):
        return self.flask_feed.generate_html_index(self.feed.retrieve_feed(), self.bridge_options, self.display_name,
                                                   self.cb_image_path, self.integration_image_path,
                                                   self.json_feed_path)

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s%s" % (self.directory, self.cb_image_path))

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(
            image_path="%s%s" % (self.directory, self.integration_image_path))

    def handle_posted_alert(self):
        """
        accept a posted alert from a FireEye device
        """
        # get the raw request contents
        # because FireEye mismatches content-type with actual content,
        # flask incorrectly decodes the data, such that request.data
        # is not valid
        #
        raw_request = flask.request.environ['body_copy']

        # decode the JSON-encoded alert
        # this only verifies that the request is JSON
        # no guarantee that it is a valid alert
        #
        # some alert data does NOT decode as JSON
        # this is an acknowledged issue from JM of FireEye
        #
        try:
            alert = cbint.utils.json.json_decode(raw_request)
        except:

            # unable to decode
            # save off the raw data for later debugging
            #
            print "Unable to parse incoming FireEye alert"
            open("%s/invalid/%s" % (self.data_dir, time.time()), "w").write(raw_request)
            raise

        # write the JSON-encoded alert to the configured data directory
        # by saving the file to disk, we can process it later with new logic
        #
        open("%s/valid/%s" % (self.data_dir, time.time()), 'w').write(raw_request)

        # process the raw alert data and generate CB-style report dictionaries
        #
        reports = self.process_alert(alert, int(time.time()))

        # add the new report to the feed
        #
        for report in reports:
            self.feed.add_report(report)

        if len(reports) > 0:
            self.feed_synchronizer.sync_needed = True

        return flask.make_response("Thanks!")

    def translate_score(self, severity):
        """
        translate a FireEye severity rating to a numeric Carbon Black score
        Carbon Black scores are in the range of [0,100]

        100 is the most severe
        """

        if not self.score_stats.has_key(severity):
            self.score_stats[severity] = 1
        else:
            self.score_stats[severity] += 1

        # per JM and ED of FireEye, only criticality rankings are
        # critical, major, and minor
        #
        if 'crit' == severity:
            return 100
        elif 'majr' == severity:
            return 75
        elif 'minr' == severity:
            return 50
        else:
            return 25

    def process_alert(self, fireeye_alert, timestamp):
        """
        process a JSON alert

        @param[in] fireeye_alert
        expectation is that alert was provided (via HTTP POST) from
        FireEye device, and is encoded with JSON.  In particular, the
        alert should be a dictionary with an 'alert' key, which will
        describe one or more actual alerts

        @param[in] timestamp
        timestamp of the alert(s) described in fireeye_alert
        as of now, this is the received timestamp _from the perspective
        of the Carbon Black bridge_.

        @retval
        returns a list of zero or more dictionaries describing Carbon
        Black reports
        """

        if 'alert' not in fireeye_alert:
            raise ValueError("No Alert")

        # a single FireEye HTTP POST may include one or more actual alert entities
        # use the integer representation of the timestamp in order to comply with
        # the feed specification, which dictates that the feed be an integer
        # note that feed_searcher cannot properly handle non-integers in certain
        # circumstances
        #
        if type(fireeye_alert['alert']) is list:
            reports = []
            for alert in fireeye_alert['alert']:
                reports.append(self.process_alert_entity(alert, int(float(timestamp))))
            return reports

        elif type(fireeye_alert['alert']) is dict:
            reports = [self.process_alert_entity(fireeye_alert['alert'], int(float(timestamp)))]
            return reports

        else:
            raise ValueError("Invalid Alert Type")

    def normalize_alert_schema(self, alert):
        """
        normalize alert schema between the 6.x.x and 7.x.x FireEye alert schemas

        in particular, translate 6.x.x alert schemas to 7.x.x schema format
        """
        for key in alert.keys():
            if type(alert[key]) is dict:
                self.normalize_alert_schema(alert[key])

            if type(alert[key]) is list:
                for i in alert[key]:
                    if type(i) is dict:
                        self.normalize_alert_schema(i)

            if key.startswith('@'):
                alert[key[1:]] = alert[key]
                del (alert[key])

        return alert

    def process_alert_entity(self, alert, timestamp):
        """
        process a single alert entity from a FireEye alert
        returns a dictionary describing the alert in terms
        of a CarbonBlack report
        """

        if type(alert) is not dict:
            raise ValueError("Invalid Alert Type")

        # the FireEye alert JSON schema changed at rev 7.0.0
        # all fields prepended with an '@' were changed to removed the '@'
        #
        # beginning in 7.0.2, a console config option on the FireEye
        # device can be set to use the 'legacy' JSON schema as opposed to the
        # new schema.  As of 13-Dec-2013, FireEye intended to make that
        # toggle a GUI option
        #
        # in order to handle alerts from 6.x.x and 7.x.x devices, including
        # 7.0.2+ devices with and without the legacy option enabled, 'scrub'
        # the incoming alert to normalize to the new JSON schema
        #
        alert = self.normalize_alert_schema(alert)

        expected_keys = ['id', 'name', 'severity', 'explanation']
        for expected_key in expected_keys:
            if expected_key not in alert:
                raise ValueError("Alert missing required key: %s" % expected_key)

        # per JM at FireEye, alerts are never unnamed
        report = {'id': alert['id'], 'link': alert.get('alert-url', ''),
                  'score': self.translate_score(alert['severity']), 'timestamp': timestamp,
                  'iocs': self.process_explanation(alert['explanation']),
                  'title': self.get_alert_name(alert['explanation'], 'Unnamed Alert')}

        return report

    def get_alert_name(self, explanation, default):
        """
        make a best-effort to retrieve the human-readable name of an alert
        """
        if 'malware' in explanation.get('malware-detected', {}):
            if type(explanation['malware-detected']['malware']) is dict:
                return explanation['malware-detected']['malware'].get('name', default)
            elif type(explanation['malware-detected']['malware']) is list:
                for entry in explanation['malware-detected']['malware']:
                    if 'name' in entry and entry['name'] != 'Suspicious.URL':
                        return entry['name']

        return default

    def process_malwaredetected(self, malwaredetected, iocs):
        """
        processes a single 'malwaredetected' entity
        this describes a piece of PE malware.  The MD5 is provided.
        updates the IOCs dictionary to include additional MD5s
        """

        if int(self.bridge_options.get('export_md5', 0)):
            if 'md5sum' in malwaredetected:
                iocs['md5'].append(malwaredetected['md5sum'])

        # urls are very interesting, but include overly wide domains (google.com, hotmail.com, etc.)
        #
        # if malwaredetected.has_key('url'):
        #    print(malwaredetected['url'].split('/')[0])
        #
        # at such time as CB supports URL indicators, these URLs can become
        # consumable by CB and therefore can be added to the feed
        #
        return iocs

    def process_cncservice(self, cncsvc, iocs):

        try:
            socket.inet_aton(cncsvc['address'])
            if int(self.bridge_options.get('export_ip', 0)):
                iocs['ipv4'].append(cncsvc['address'])
        except:
            if int(self.bridge_options.get('export_dns', 0)):
                iocs['dns'].append(cncsvc['address'])

        return iocs

    def process_explanation(self, explanation):
        iocs = {'md5': [], 'ipv4': [], 'dns': []}

        if explanation.has_key('cnc-services') and explanation['cnc-services'].has_key('cnc-service'):
            if type({}) == type(explanation['cnc-services']['cnc-service']):
                iocs = self.process_cncservice(explanation['cnc-services']['cnc-service'], iocs)
            elif type([]) == type(explanation['cnc-services']['cnc-service']):
                for cncsvc in explanation['cnc-services']['cnc-service']:
                    iocs = self.process_cncservice(cncsvc, iocs)

        if explanation.has_key('malware-detected') and explanation['malware-detected'].has_key('malware'):
            if type({}) == type(explanation['malware-detected']['malware']):
                iocs = self.process_malwaredetected(explanation['malware-detected']['malware'], iocs)
            elif type([]) == type(explanation['malware-detected']['malware']):
                for malware in explanation['malware-detected']['malware']:
                    iocs = self.process_malwaredetected(malware, iocs)

        return iocs

    def restore_alerts(self):
        """
        restore alerts from disk
        """
        num_restored = 0

        alert_filenames = os.listdir('%s/valid' % self.data_dir)
        for alert_filename in alert_filenames:

            try:

                # alerts 'expire' after a configure period of time
                # to support that, determine the timestamp of 'now' as well as the
                # timestamp of the alert
                #
                now = int(time.time())

                matches = digit_re.match(alert_filename)
                if not matches:
                    logger.warn("Saved alert '%s' did not include a valid date-time stamp" % alert_filename)
                    continue

                then = int(matches.group(1))

                # skip alerts that have expired based on configured ttl
                #
                if 'alert_ttl' in self.bridge_options and (now - then) > int(self.bridge_options['alert_ttl']):
                    continue

                # read the alert file from disk and decode it's contents as JSON
                #
                alert = cbint.utils.json.json_decode(open('%s/valid/%s' % (self.data_dir, alert_filename)).read())

                # process the raw alert data and generate CB-style report dictionaries
                #
                reports = self.process_alert(alert, then)

                # add the new report to the feed
                #
                for report in reports:
                    self.feed.add_report(report)

            except Exception as e:
                logger.warn("Failure processing saved alert '%s' [%s]" % (alert_filename, e))
                continue

            num_restored += 1

        return num_restored

    def validate_config(self):
        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            logger.error("configuration does not contain a [bridge] section")
            return False

        config_valid = True
        msgs = []
        if not 'listener_port' in self.bridge_options or not self.bridge_options['listener_port'].isdigit():
            msgs.append('the config option listener_port is required and must be a valid port number')
            config_valid = False
        if not 'carbonblack_server_url' in self.bridge_options:
            msgs.append('the config option carbonblack_server_url is required')
            config_valid = False
        if not 'carbonblack_server_token' in self.bridge_options:
            msgs.append('the config option carbonblack_server_token is required')
            config_valid = False

        if not config_valid:
            for msg in msgs:
                sys.stderr.write("%s\n" % msg)
                logger.error(msg)
            return False
        else:
            return True
