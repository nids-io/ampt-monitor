'''
AMPT Monitor command line interface

'''
import sys
import logging
import argparse

from configobj import ConfigObj

from . import settings
from . import __application_name__
from . import __version__ as ampt_mon_version
from .amptmonitor import AMPTMonitor


LOGLEVEL_CHOICES = ['debug', 'info', 'warning', 'error', 'critical']

# Setuptools entry point common namespace
EP_NAMESPACE = 'ampt_monitor.plugin'

logger = logging.getLogger(__application_name__)

def main():
    description = 'Event log monitor utility for the AMPT passive tools monitor'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-c', '--config', default=settings.DEFAULT_CONFIG_PATH,
                        help='configuration file path (default: %(default)s)')
    parser.add_argument('-o', '--logfile',
                        help='log to specified file (default: do not log to file)')
    parser.add_argument('-l', '--loglevel', choices=LOGLEVEL_CHOICES,
                        help=('set logging level to specified verbosity '
                              '(default: %s)' % settings.DEFAULT_LOGLEVEL))
    parser.add_argument('-u', '--user', help='user as which to run program')
    parser.add_argument('-g', '--group', help='group as which to run program')
    parser.add_argument('-n', '--no-verify-ssl', action='store_true',
                        help=('disable certificate verification for connection '
                              'to AMPT Manager'))
    args = parser.parse_args()

    config = ConfigObj(args.config)

    user = args.user or config.get('user')
    group = args.group or config.get('group')
    logfile = args.logfile or config.get('logfile')
    loglevel = (args.loglevel or config.get('loglevel')
                or settings.DEFAULT_LOGLEVEL).upper()
    try:
        conf_cert_verification = config.as_bool('disable_cert_verification')
    except KeyError:
        conf_cert_verification = False
    verify_cert = not (args.no_verify_ssl or conf_cert_verification)

    app_formatter = settings.LOG_FORMATTER
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(loglevel)
    stream_handler.setFormatter(app_formatter)
    logger.addHandler(stream_handler)
    logger.setLevel(loglevel)

    if logfile:
        try:
            file_formatter = settings.LOG_FORMATTER
            file_handler = logging.FileHandler(logfile)
            file_handler.setLevel(loglevel)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except OSError as e:
            msg = 'failure opening log file (%s)'
            logger.critical(msg, e)
            sys.exit(1)

    ver_info = 'starting %s %s on Python %s'
    py_version = '.'.join([str(x) for x in sys.version_info[:3]])
    logger.info(ver_info, __application_name__, ampt_mon_version, py_version)
    logger.debug('AMPT Manager SSL certificate verification is %s',
                 'enabled' if verify_cert else 'disabled')

    # Dictionary of monitor configs
    conf_monitors = config.get(settings.MONITOR_SECTION, {})
    logger.debug('monitors (conf_monitors) configured as %s', conf_monitors)

    # Dictionary of HMAC parameters
    hmac_params = {
        'key': config['hmac_key'],
        'hash': config.get('hmac_digest') or settings.DEFAULT_HMAC_DIGEST,
    }

    logger.debug('loading AMPT Monitor core')
    ampt_monitor = AMPTMonitor(
        config['url'],
        hmac_params,
        monitors=conf_monitors,
        user=user,
        group=group,
        verify_cert=verify_cert,
    )

    logger.debug('running AMPT Monitor')
    ampt_monitor.run()

