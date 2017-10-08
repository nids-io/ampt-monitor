'''
AMPT Monitor core settings & defaults

'''
import logging


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

