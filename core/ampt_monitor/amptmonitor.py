'''
AMPT monitor core

'''
import os
import grp
import pwd
import logging
import multiprocessing

import requests
from stevedore import driver

from . import settings
from . import __application_name__
from .notify import notify_manager


logger = logging.getLogger(__application_name__)

class AMPTMonitor:
    def __init__(self, manager_url, hmac_params, monitors={}, user=None,
                 group=None, verify_cert=True):
        '''Create new AMPT Monitor instance.

        :param manager_url: AMPT Manager log receipt URL
        :param hmac_params: dictionary containing keys for HMAC key and
                            digest to use
        :param monitors:    dictionary containing map of configured monitors
                            (typically parsed from config file)
        :param user:        user to run as
        :param group:       group to run as
        :param verify_cert: whether to validate SSL certificate when
                            connecting to AMPT Manager
        :return:            new AMPT Monitor instance

        '''
        self.manager_url = manager_url
        self.hmac_params = hmac_params
        self.monitors = monitors or None
        self.user = user
        self.group = group
        self.verify_cert = verify_cert

        # Drop privileges if running as superuser
        if os.getuid() == 0:
            logger.debug('dropping privileges...')
            _drop_privileges(user=self.user, group=self.group)
        running_user = pwd.getpwuid(os.getuid()).pw_name
        running_group = grp.getgrgid(os.getgid()).gr_name
        logger.debug('AMPT Monitor initialized as user %s, group %s',
                         running_user, running_group)

    def run(self):
        'Fork monitor processes and invoke plugins.'

        if self.monitors:
            # Use a queue to allow monitor plugins to put logs in for the core
            # to pull out and notify the AMPT Manager. Queue size is not
            # expected to be important and rate of handling objects should be
            # low, but we use a limit to give us ability to spot problems where
            # the queue is for some reason not being emptied.
            queue = multiprocessing.Queue(settings.QUEUE_MAXSIZE)

            # List of monitor plugin names to load
            self.plugins = self.monitors.keys()

            # Dynamically load and configure monitor plugins as stevedore drivers
            logger.debug('loading monitor plugins from %s namespace',
                         settings.EP_NAMESPACE)
            self.loaded_monitors = []
            for plugin in self.plugins:
                mgr = driver.DriverManager(
                    namespace=settings.EP_NAMESPACE,
                    name=plugin,
                )
                self.loaded_monitors.append(mgr)
                logger.info('loaded monitor plugin: %s', plugin)

                # Instantiate plugin, passing in shared queue and configuration
                # dictionary
                monitor_plugin = mgr.driver(queue=queue, plugin_name=plugin,
                                            **self.monitors[plugin])

                # Construct plugin subprocess object
                proc = multiprocessing.Process(
                           target=monitor_plugin.run,
                           name='Plugin[{}]'.format(plugin),
                       )
                logger.debug('invoking subprocess for %s plugin as %s',
                             plugin, proc.name)
                proc.start()

            logger.debug('completed starting monitor plugin classes: %s',
                         [m.driver for m in self.loaded_monitors])

            logger.debug('starting message retrieval loop from shared queue')
            while True:
                logger.debug('awaiting event messages from monitor plugins...')
                evt = queue.get()
                logger.debug('received new log event from monitor plugin')
                notify_manager(self.manager_url, evt, self.hmac_params,
                               self.verify_cert)

def _drop_privileges(user, group):
    '''Drop privileges to execute as non-root user

    :param user: User name
    :param group: Group
    :return:

    '''
    if user is None:
        user = settings.USER
    if group is None:
        group = settings.GROUP

    new_uid = pwd.getpwnam(user).pw_uid
    new_gid = grp.getgrnam(group).gr_gid
    os.setgroups([])
    os.setgid(new_gid)
    os.setuid(new_uid)
    os.umask(0o077)

