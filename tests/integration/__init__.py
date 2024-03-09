import os.path

from ipaddress import ip_address, ip_network
from unittest.mock import patch

import cert_checker

from tests.unit import ServiceTestBase


class TestCertChecker(ServiceTestBase):
    """Test against real certificates on the Internet"""

    services = {
        'amazon.com': (443, ip_network('52.88.0.0/13')),
        'google.com': (443, ip_network('142.250.0.0/15')),
    }

    def setUp(self):
        super(TestCertChecker, self).setUp()
        self.environ[cert_checker.CFG_INSTANCES_FILE] = os.path.join(*__path__, 'addrs.txt')

    @patch('cert_checker.StatsDSink', autospec=True)
    @patch('cert_checker.SlackNotifier', autospec=True)
    @patch.object(cert_checker.os, 'environ', autospec=True)
    def test(self, mock_os_environ, mock_notifier, mock_statsd_sink):
        mock_os_environ.get.side_effect = self.environ.get

        app = cert_checker.CertChecker()
        app.configure()
        app.run()

        amazon_stats = app.config.services['amazon.com'].stats
        self.assertEqual(amazon_stats.outdated.value, 1)
        self.assertEqual(amazon_stats.expiring.value, 0)
        self.assertEqual(amazon_stats.expired.value, 0)
        self.assertEqual(amazon_stats.errors.value, 0)

        google_stats = app.config.services['google.com'].stats
        self.assertEqual(google_stats.outdated.value, 1)
        self.assertEqual(google_stats.expiring.value, 0)
        self.assertEqual(google_stats.expired.value, 0)
        self.assertEqual(google_stats.errors.value, 0)

        app.config.statsd_sink.write.assert_called_once()
