import json
import logging
import os
import socket
import ssl
import sys
import typing
import urllib.request

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network


# Common logger
logger = logging.getLogger(__name__)


# Environment variables used to configure the application
CFG_LOG_LEVEL       = 'LOG_LEVEL'
CFG_INSTANCES_FILE  = 'INSTANCES_FILE'
CFG_SERVICES        = 'SERVICES'
CFG_STATSD_ADDR     = 'STATSD_ADDR'
CFG_SLACK_WEBHOOK   = 'SLACK_WEBHOOK'
CFG_FRESHNESS_DAYS  = 'FRESHNESS_DAYS'
CFG_EXPIRATION_DAYS = 'EXPIRATION_DAYS'
CFG_CHECK_SAN       = 'CHECK_SAN'

# Default values for configuration variables
CFG_DEFAULTS = {
    CFG_LOG_LEVEL:       'info',
    CFG_INSTANCES_FILE:  'takehome_ip_addresses.txt',
    CFG_SERVICES:        'Europa:4000=10.10.6.0/24,Callisto:8000=10.10.8.0/24',
    CFG_STATSD_ADDR:     '10.10.4.14:8125',
    CFG_SLACK_WEBHOOK:   'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    CFG_FRESHNESS_DAYS:  '7',
    CFG_EXPIRATION_DAYS: '30',
    CFG_CHECK_SAN:       'true',
}

# Used to parse boolean configuration variables
TRUE_STRING_VALUES = frozenset(('1', 'true', 'yes'))

# Used to parse issue/expiration dates in SSL certificates
CERT_DATE_FORMAT = '%b %d %H:%M:%S %Y %Z'

# Common timeout for TCP socket connection operations
SOCKET_TIMEOUT = 10
# Default StatsD port to send metrics to if unspecified
STATSD_PORT = 8125

# Stubs for fancy formatting when sending Slack notifications
MSG_WARNING_PREFIX  = '⚠️  '
MSG_ERROR_PREFIX    = '❌ '
MSG_CRITICAL_PREFIX = '🆘 '

MSG_LOG_PREFIX = '[{name}:{port}]'

# Templates for error messages sent to logs and as Slack notifications
MSG_CONNECTION_ERROR   = '{prefix} could not connect to {addr!s}: {exc!s}'
MSG_VERIFICATION_ERROR = '{prefix} could not verify the certificate of {addr!s}: {exc!s}'

MSG_CERT_OUTDATED = '{prefix} certificate of {addr!s} is outdated with the issue timestamp "{ts}"'
MSG_CERT_EXPIRING = '{prefix} certificate of {addr!s} expired on "{ts}"'
MSG_CERT_EXPIRED  = '{prefix} certificate of {addr!s} is about to expire on "{ts}"'
MSG_STATSD_ERROR  = 'Error writing to StatsD at {addr}:{port}: {exc!s}'


@dataclass
class StatsDMetric:
    """Base class for StatsD metrics"""

    name: str

    def __str__(self) -> str:
        raise NotImplemented


@dataclass
class StatsDGauge(StatsDMetric):
    """StatsD gauge metric"""

    value: int = 0

    def __str__(self) -> str:
        """Serialize to StatsD wire metric format"""

        return f'{self.name}:{self.value}|g'


@dataclass
class Stats:
    """Tracked metrics for instance certificates of a Service"""

    outdated: StatsDGauge
    expiring: StatsDGauge
    expired:  StatsDGauge
    errors:   StatsDGauge

    def get_metrics(self) -> typing.List[StatsDMetric]:
        """Collect metrics to send to StatsD, so they can be merged with others and sent in
        a single batch"""

        metrics = [
            self.outdated,
            self.expiring,
            self.expired,
            self.errors,
        ]

        return metrics


@dataclass
class StatsDSink:
    """Wrapper to send metrics to StatsD"""

    host: str
    port: int = STATSD_PORT

    def write(self, *metrics):
        """Serialize metrics and send to StatsD"""

        raw_metrics = []
        for metric in metrics:
            assert isinstance(metric, StatsDMetric)
            raw_metrics.append(str(metric))

        raw_data = '\n'.join(raw_metrics).encode()
        logger.debug('About to send a StatsD message: {!r}'.format(raw_data))
        self._send(raw_data)

    def _send(self, data: str):
        """Write serialized metrics to StatsD"""

        logger.info(f'Writing {len(data)} bytes to {self.host}:{self.port}')

        with socket.socket() as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect((self.host, self.port))
            sock.write(data)


@dataclass
class SlackNotifier:
    """Wrapper to log messages and send them as Slack notifications"""

    webhook_url: str

    def warning(self, message: str):
        """Process a warning message"""

        logger.warning(message)
        slack_message = MSG_WARNING_PREFIX + message
        self._send_slack_message(slack_message)

    def error(self, message: str):
        """Process an urgent message"""

        logger.error(message)
        slack_message = MSG_ERROR_PREFIX + message
        self._send_slack_message(slack_message)

    def critical(self, message: str):
        """Process an extremely urgent message"""

        logger.critical(message)
        slack_message = MSG_CRITICAL_PREFIX + message
        self._send_slack_message(slack_message)

    def _send_slack_message(self, message):
        """Prepare and send a Slack Webhook payload"""

        logger.debug(f'Sending Slack message: {message!r}')

        try:
            body = json.dumps({'text': message}).encode()

            req = urllib.request.Request(
                method='POST',
                url=self.webhook_url,
                data=body,
                headers={'content-type': 'application/json'},
            )

            with urllib.request.urlopen(req) as resp:
                if resp.status != 200:
                    data = resp.read().decode('utf-8')
                    logger.error(f'Incorrect Slack Webhook response: [{resp.status}] {data}')
        except Exception as exc:
            logger.error(f'Could not send slack notification: {exc!s}')


@dataclass
class Service:
    """Service subject to the check of instance certificates"""

    name:      str
    port:      int
    net:       ip_network
    instances: typing.List[ip_address] = field(default_factory=list)
    stats:     Stats = None

    def __post_init__(self):
        """Initialize metrics for instance certificates"""

        if self.stats is None:
            name = self.name.replace('.', '_')
            self.stats = Stats(
                outdated = StatsDGauge(f'certs.{name}.outdated'),
                expiring = StatsDGauge(f'certs.{name}.expiring'),
                expired  = StatsDGauge(f'certs.{name}.expired'),
                errors   = StatsDGauge(f'certs.{name}.errors'),
            )

    def check_certificates(self, check_san: bool, notifier: SlackNotifier,
        freshness_td: timedelta, expiration_td: timedelta):
        """Check SSL certificates for each instance"""

        name = self.name
        port = self.port

        ctx = ssl.create_default_context()
        ctx.check_hostname = check_san

        log_prefix = MSG_LOG_PREFIX.format(name=name, port=port)
        logger.info(f'{log_prefix} checking certificates for {len(self.instances)} instances')

        for addr in self.instances:
            with socket.socket() as sock:
                sock.settimeout(SOCKET_TIMEOUT)
                try:
                    sock.connect((str(addr), port))
                except Exception as exc:
                    self.stats.errors.value += 1
                    notifier.warning(MSG_CONNECTION_ERROR.format(
                        prefix=log_prefix, addr=addr, exc=exc,
                    ))
                    continue

                logger.info(f'{log_prefix} connected to {addr!s}')

                with ctx.wrap_socket(sock, server_hostname=name) as ssock:
                    try:
                        cert = ssock.getpeercert()
                        logger.debug(f'{log_prefix} certificate of {addr!s}: {cert!r}')
                        self._verify_certificate(addr, cert, notifier, freshness_td, expiration_td)
                    except Exception as exc:
                        self.stats.errors.value += 1
                        notifier.warning(MSG_VERIFICATION_ERR.format(
                            prefix=log_prefix, addr=addr, exc=exc,
                        ))

        logger.info('{log_prefix} outdated: {outdated} expiring: {expiring} expired: {expired} '
            'errors: {errors}'.format(
                log_prefix=log_prefix,
                outdated=self.stats.outdated.value,
                expiring=self.stats.expiring.value,
                expired=self.stats.expired.value,
                errors=self.stats.errors.value,
            )
        )

    def _verify_certificate(self, addr: ip_address, cert: dict, notifier: SlackNotifier,
        freshness_td: timedelta, expiration_td: timedelta):
        """Verify the certificate of an instance.

        Update stats and send out certificate-related notifications as needed."""

        nbf_str = cert['notBefore']
        exp_str = cert['notAfter']

        iat = datetime.strptime(nbf_str, CERT_DATE_FORMAT)
        exp = datetime.strptime(exp_str, CERT_DATE_FORMAT)

        now = datetime.utcnow()
        since_issue = now - iat
        till_expiry = exp - now

        log_prefix = MSG_LOG_PREFIX.format(name=self.name, port=self.port)
        if since_issue > freshness_td:
            self.stats.outdated.value += 1
            notifier.warning(MSG_CERT_OUTDATED.format(prefix=log_prefix, addr=addr, ts=nbf_str))

        if now >= exp:
            self.stats.expired.value += 1
            notifier.critical(MSG_CERT_EXPIRED.format(prefix=log_prefix, addr=addr, ts=exp_str))
        elif till_expiry <= expiration_td:
            self.stats.expiring.value += 1
            notifier.error(MSG_CERT_EXPIRING.format(prefix=log_prefix, addr=addr, ts=exp_str))


@dataclass
class Config:
    """Configuration of the checker application"""

    services:       typing.Dict[str, Service]
    statsd_sink:    StatsDSink
    slack_notifier: SlackNotifier
    freshness_td:   timedelta
    expiration_td:  timedelta
    check_san:      bool = True


class CertChecker:
    """The checker application proper"""

    config: Config

    def __init__(self):
        """Initialize configuration for a new instance of the application"""

        log_level = os.environ.get(CFG_LOG_LEVEL, CFG_DEFAULTS[CFG_LOG_LEVEL])
        logger.setLevel(log_level.upper())

        statsd_cfg = os.environ.get(CFG_STATSD_ADDR, CFG_DEFAULTS[CFG_STATSD_ADDR]).split(':')
        statsd_host = statsd_cfg[0]
        statsd_port = int(statsd_cfg[1]) if len(statsd_cfg) > 1 else STATSD_PORT
        statsd_sink = StatsDSink(statsd_host, statsd_port)

        webhook_url = os.environ.get(CFG_SLACK_WEBHOOK, CFG_DEFAULTS[CFG_SLACK_WEBHOOK])
        slack_notifier = SlackNotifier(webhook_url)

        freshness_days = os.environ.get(CFG_FRESHNESS_DAYS, CFG_DEFAULTS[CFG_FRESHNESS_DAYS])
        freshness_td = timedelta(days=int(freshness_days))

        expiration_days = os.environ.get(CFG_EXPIRATION_DAYS, CFG_DEFAULTS[CFG_EXPIRATION_DAYS])
        expiration_td = timedelta(days=int(expiration_days))

        check_san_cfg = os.environ.get(CFG_CHECK_SAN, CFG_DEFAULTS[CFG_CHECK_SAN])
        check_san = check_san_cfg.lower() in TRUE_STRING_VALUES

        self.config = Config(
            [], statsd_sink, slack_notifier, freshness_td, expiration_td, check_san,
        )

    def configure(self):
        """Parse configuration for Services and their instance addresses"""

        instances_file = os.environ.get(CFG_INSTANCES_FILE, CFG_DEFAULTS[CFG_INSTANCES_FILE])
        instances = self._get_configured_instances(instances_file)

        services_config = os.environ.get(CFG_SERVICES, CFG_DEFAULTS[CFG_SERVICES])
        services = self._get_configured_services(services_config, instances)

        self.config.services = services

    def _get_configured_instances(self, instances_file: str) -> typing.List[ip_address]:
        """Read the file containing one IP address per line and return the list of ip_address
        objects. Omit empty lines and comments starting with '#'."""

        instances = []
        with open(instances_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                addr = ip_address(line)
                instances.append(addr)

        return instances

    def _get_configured_services(self, services_config: str, instances: typing.List[ip_address]) \
        -> typing.Dict[str, Service]:
        """Parse the specification in the format 'service:port=cidr,...' and return the map of
        Services with respective instance addresses"""

        services = {}
        addresses = set(instances)

        service_specs = services_config.split(',')
        for svc_spec in service_specs:
            svc_hostport, svc_cidr = svc_spec.strip().split('=')
            svc_name, svc_port = svc_hostport.split(':')

            net = ip_network(svc_cidr)
            port = int(svc_port)

            svc_addrs = []
            addrs_left = set()
            while addresses:
                addr = addresses.pop()
                if addr in net:
                    svc_addrs.append(addr)
                else:
                    addrs_left.add(addr)

            addresses = addrs_left
            svc_addrs.sort()

            svc = Service(svc_name, port, net, svc_addrs)
            services[svc_name] = svc

        return services

    def run(self):
        """Perform certificate checks and report metrics"""

        self._check_certificates()
        self._report_metrics()

    def _check_certificates(self):
        """Check certificates for each service"""

        logger.info('Running certificate checks for {} services'.format(len(self.config.services)))

        check_san = self.config.check_san
        notifier = self.config.slack_notifier
        freshness_td = self.config.freshness_td
        expiration_td = self.config.expiration_td

        for service in self.config.services.values():
            service.check_certificates(check_san, notifier, freshness_td, expiration_td)

        logger.info('Certificate checks completed')

    def _report_metrics(self):
        """Collect certificate metrics from each service and send the batch to StatsD"""

        logger.info('Collecting metrics for {} services'.format(len(self.config.services)))

        metrics = []
        for service in self.config.services.values():
            svc_metrics = service.stats.get_metrics()
            metrics.extend(svc_metrics)

        logger.info('Reporting {} metrics'.format(len(metrics)))

        try:
            self.config.statsd_sink.write(*metrics)
        except Exception as exc:
            self.config.slack_notifier.warning(MSG_STATSD_ERROR.format(
                addr=self.config.statsd_sink.host,
                port=self.config.statsd_sink.port,
                exc=exc,
            ))
        else:
            logger.info('Reporting done')
