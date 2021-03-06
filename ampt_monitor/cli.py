'''
AMPT Monitor command line interface

'''
import os
import sys
import logging
import argparse

from configobj import ConfigObj

from . import settings
from . import get_ampt_version
from . import __application_name__
from .amptmonitor import AMPTMonitor
from .exceptions import AMPTMonitorException


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
                              '(default: %s)' % settings.DEFAULT_STREAM_LOGLEVEL))
    parser.add_argument('-u', '--user', help='user as which to run program')
    parser.add_argument('-g', '--group', help='group as which to run program')
    parser.add_argument('-n', '--no-verify-ssl', action='store_true',
                        help=('disable certificate verification for connection '
                              'to AMPT Manager'))
    parser.add_argument('-V', '--version', action='store_true',
                        help='display version and exit')
    args = parser.parse_args()

    # Handle special case of version output.
    if args.version:
        parser.exit(status=0,
                    message=get_ampt_version(with_plugins=True) + '\n')

    config = ConfigObj(args.config)

    user = args.user or config.get('user')
    group = args.group or config.get('group')
    logfile = args.logfile or config.get('logfile')
    loglevel_stream = (args.loglevel or config.get('loglevel')
                or settings.DEFAULT_STREAM_LOGLEVEL).upper()
    loglevel_file = (args.loglevel or config.get('loglevel')
                or settings.DEFAULT_FILE_LOGLEVEL).upper()
    try:
        conf_cert_verification = config.as_bool('disable_cert_verification')
    except KeyError:
        conf_cert_verification = False
    verify_cert = not (args.no_verify_ssl or conf_cert_verification)

    app_formatter = settings.LOG_FORMATTER
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(loglevel_stream)
    stream_handler.setFormatter(app_formatter)
    logger.addHandler(stream_handler)
    logger.setLevel(loglevel_stream)

    if logfile:
        try:
            file_formatter = settings.LOG_FORMATTER
            file_handler = logging.FileHandler(logfile)
            file_handler.setLevel(loglevel_file)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            logger.setLevel(loglevel_file)
        except OSError as e:
            msg = 'failure opening log file (%s)'
            logger.critical(msg, e)
            sys.exit(1)

    ver_info = 'starting %s on Python %s'
    py_version = '.'.join([str(x) for x in sys.version_info[:3]])
    logger.info(ver_info, get_ampt_version(), py_version)
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
    try:
        ampt_monitor.run()
    except AMPTMonitorException as e:
        logger.exception(e)
        parser.exit(status=1)
