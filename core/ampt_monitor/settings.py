'''
AMPT Monitor core settings & defaults

'''
import logging


# Default application configuration file path
DEFAULT_CONFIG_PATH = '/etc/ampt-monitor.conf'
# Name of section for monitors configuration in config file
MONITOR_SECTION = 'monitors'
# Setuptools entry point common namespace for plugins
EP_NAMESPACE = 'ampt_monitor.plugin'
# User and group for dropping priviliges when run as superuser
USER = 'nobody'
GROUP = 'nogroup'
# Maximum queue size - simple resource constraint
QUEUE_MAXSIZE = 5
# Default log format
LOG_FORMATTER = logging.Formatter('%(asctime)s [%(levelname)s] '
                                  '%(processName)s (pid: %(process)d): '
                                  '%(module)s - %(message)s'
                                 )
# Default logging level
DEFAULT_LOGLEVEL = 'warning'
# Default HMAC hash
DEFAULT_HMAC_DIGEST = 'sha256'
