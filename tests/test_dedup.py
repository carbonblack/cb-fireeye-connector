__author__ = 'jgarman'

import sys
sys.path.append("../src")

from cbfireeyebridge.bridge import CarbonBlackFireEyeBridge, DedupFeedIOCReports, SimpleFeedReport
import unittest
import os
import json


class TestIOCDeduplication(unittest.TestCase):
    def setUp(self):
        self.event_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_alerts", "valid")

    def test_deduplication(self):
        bridge1 = CarbonBlackFireEyeBridge("fireeye", "testing.conf", logfile="/tmp/fireeye1.log",
                                           pidfile="/tmp/fireeye1.pid", debug=True)
        bridge1.validate_config()

        feed_raw = SimpleFeedReport({})
        feed_dedup = DedupFeedIOCReports({})

        for fn in os.listdir(self.event_directory):
            timestamp = float(fn.strip('.dat'))
            alert_data = json.load(open(os.path.join(self.event_directory, fn), 'rb'))
            try:
                reports = bridge1.process_alert(alert_data, int(timestamp))
                for report in reports:
                    feed_raw.add_report(report)
                    feed_dedup.add_report(report)
            except ValueError as e:
                print e

        raw_reports = feed_raw.retrieve_feed()["reports"]
        dedup_reports = feed_dedup.retrieve_feed()["reports"]

        raw_iocs = []
        dedup_iocs = []

        for raw_report in raw_reports:
            ioc = raw_report["iocs"]
            raw_iocs.append(ioc)

        for dedup_report in dedup_reports:
            ioc = dedup_report["iocs"]
            dedup_iocs.append(ioc)

        failures = []
        for raw_ioc in raw_iocs:
            if raw_ioc not in dedup_iocs:
                failures.append("Could not find IOC %s in dedup set" % raw_ioc)

        self.assertIs(len(failures), 0, msg='\n'.join(failures))

        print "%d reports in raw set; %d in dedup set" % (len(raw_reports), len(dedup_reports))
