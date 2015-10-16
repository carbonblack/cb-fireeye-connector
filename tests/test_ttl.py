__author__ = 'jgarman'

import sys
sys.path.append("../src")

from cbfireeyebridge.bridge import CarbonBlackFireEyeBridge, DedupFeedIOCReports, SimpleFeedReport
import unittest
import os


class TestTimeToLive(unittest.TestCase):
    def setUp(self):
        self.event_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_alerts")

    def test_ttl(self):
        bridge1 = CarbonBlackFireEyeBridge("fireeye", "testing.conf", logfile="/tmp/fireeye1.log",
                                           pidfile="/tmp/fireeye1.pid", debug=True, data_dir=self.event_directory)
        bridge1.validate_config()

        restored = bridge1.restore_alerts()
        self.assertEqual(restored, 0)

    def test_no_ttl(self):
        bridge1 = CarbonBlackFireEyeBridge("fireeye", "testing.conf", logfile="/tmp/fireeye1.log",
                                           pidfile="/tmp/fireeye1.pid", debug=True, data_dir=self.event_directory)
        bridge1.validate_config()
        del bridge1.bridge_options['alert_ttl']

        restored = bridge1.restore_alerts()
        self.assertNotEqual(restored, 0)
