from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from unittest import TestCase
from unittest.mock import patch

import cert_checker


ONE_MINUTE = timedelta(seconds=60)


class ServiceTestBase(TestCase):
    def setUp(self):
        self.environ = {
            cert_checker.CFG_SERVICES: ','.join((
                f'{name}:{port!s}={net!s}' for name, (port, net) in self.services.items()
            ))
        }


class TestServiceConfig(ServiceTestBase):
    """Make sure Service configurations are parsed correctly"""

    services = {
        'one':   (8181, ip_network('10.0.1.0/24')),
        'two':   (8282, ip_network('10.0.2.0/24')),
        'three': (8383, ip_network('10.0.3.0/24')),
    }

    addresses = [
        ip_address(_) for _ in [
            '10.0.1.1',
            '10.0.1.2',
            '10.0.2.3',
            '10.0.0.4',
        ]
    ]

    @patch.object(cert_checker.os, 'environ', autospec=True)
    @patch.object(cert_checker.CertChecker, '_get_configured_instances', autospec=True)
    def test(self, mock_get_configured_instances, mock_os_environ):
        mock_os_environ.get.side_effect = self.environ.get
        mock_get_configured_instances.return_value = self.addresses

        app = cert_checker.CertChecker()
        app.configure()

        services = app.config.services
        self.assertEqual(len(services), len(self.services))

        for name, (port, net) in self.services.items():
            self.assertEqual(services[name].net, net)
            self.assertEqual(services[name].port, port)

        self.assertEqual(len(services['one'].instances), 2)
        self.assertEqual(len(services['two'].instances), 1)
        self.assertEqual(len(services['three'].instances), 0)


class TestCertVerification(TestCase):
    """Make sure certificate issue/expiration is verified properly"""

    app  = cert_checker.CertChecker()
    addr = ip_address('10.0.0.1')

    def getService(self):
        return cert_checker.Service('test', 8080, ip_network('10.0.0.0/24'), [])

    @patch('cert_checker.SlackNotifier', autospec=True)
    def test_freshness(self, notifier_mock):
        config = self.app.config

        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        iat = now - config.freshness_td - ONE_MINUTE
        exp = now + config.expiration_td + ONE_MINUTE

        cert = {
            'notBefore': iat.strftime(cert_checker.CERT_DATE_FORMAT),
            'notAfter':  exp.strftime(cert_checker.CERT_DATE_FORMAT),
        }

        svc = self.getService()
        svc._verify_certificate(self.addr, cert, notifier_mock, config.freshness_td,
            config.expiration_td)

        self.assertEqual(svc.stats.outdated.value, 1)
        self.assertEqual(svc.stats.expiring.value, 0)
        self.assertEqual(svc.stats.expired.value, 0)
        self.assertEqual(svc.stats.errors.value, 0)

        msg = cert_checker.MSG_CERT_OUTDATED.format(
            prefix=cert_checker.MSG_LOG_PREFIX.format(name=svc.name, port=svc.port),
            addr=self.addr,
            ts=cert['notBefore'],
        )
        notifier_mock.warning.assert_called_once_with(msg)
        notifier_mock.error.assert_not_called()
        notifier_mock.critical.assert_not_called()

    @patch('cert_checker.SlackNotifier', autospec=True)
    def test_expiration(self, notifier_mock):
        config = self.app.config

        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        iat = now - ONE_MINUTE
        exp = now + config.expiration_td - ONE_MINUTE

        cert = {
            'notBefore': iat.strftime(cert_checker.CERT_DATE_FORMAT),
            'notAfter':  exp.strftime(cert_checker.CERT_DATE_FORMAT),
        }

        svc = self.getService()
        svc._verify_certificate(self.addr, cert, notifier_mock, config.freshness_td,
            config.expiration_td)

        self.assertEqual(svc.stats.outdated.value, 0)
        self.assertEqual(svc.stats.expiring.value, 1)
        self.assertEqual(svc.stats.expired.value, 0)
        self.assertEqual(svc.stats.errors.value, 0)

        msg = cert_checker.MSG_CERT_EXPIRING.format(
            prefix=cert_checker.MSG_LOG_PREFIX.format(name=svc.name, port=svc.port),
            addr=self.addr,
            ts=cert['notAfter'],
        )
        notifier_mock.warning.assert_not_called()
        notifier_mock.error.assert_called_once_with(msg)
        notifier_mock.critical.assert_not_called()

    @patch('cert_checker.SlackNotifier', autospec=True)
    def test_expired(self, notifier_mock):
        config = self.app.config

        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        iat = now - ONE_MINUTE * 2
        exp = now - ONE_MINUTE

        cert = {
            'notBefore': iat.strftime(cert_checker.CERT_DATE_FORMAT),
            'notAfter':  exp.strftime(cert_checker.CERT_DATE_FORMAT),
        }

        svc = self.getService()
        svc._verify_certificate(self.addr, cert, notifier_mock, config.freshness_td,
            config.expiration_td)

        self.assertEqual(svc.stats.outdated.value, 0)
        self.assertEqual(svc.stats.expiring.value, 0)
        self.assertEqual(svc.stats.expired.value, 1)
        self.assertEqual(svc.stats.errors.value, 0)

        msg = cert_checker.MSG_CERT_EXPIRED.format(
            prefix=cert_checker.MSG_LOG_PREFIX.format(name=svc.name, port=svc.port),
            addr=self.addr,
            ts=cert['notAfter'],
        )
        notifier_mock.warning.assert_not_called()
        notifier_mock.error.assert_not_called()
        notifier_mock.critical.assert_called_once_with(msg)
