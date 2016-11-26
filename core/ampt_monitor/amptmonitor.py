'''
AMPT monitor core
'''

from builtins import object
import os
import pwd
import grp
import time
import logging
import multiprocessing

import requests


class AmptMonitor(object):
    def __init__(self, monitors, logfile, loglevel, user, group, url, monitor_id):
        self.logger = logging.getLogger('AmptMonitor')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        fh = logging.FileHandler(logfile)
        fh.setLevel(loglevel)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setLevel(loglevel)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        self.logger.info('logging to {logfile} with loglevel {loglevel}'
                         .format(logfile=logfile, loglevel=loglevel))
        self.monitors = monitors
        self.user = user
        self.group = group
        self.url = url
        self.monitor_id = monitor_id

    def _post(self, data):
        return requests.post(self.url, data=data)

    def run(self):
        self.logger.info('Starting monitors')
        for monitor in self.monitors:
            self.logger.info('monitor with path {logfile}'
                             .format(logfile=monitor.logfile))
            tailer = multiprocessing.Process(target=self._tail, args=(monitor, ))
            processor = multiprocessing.Process(target=self.ampt_process, args=(monitor, ))
            tailer.start()
            processor.start()

    def ampt_process(self, monitor):
        self._drop_privileges()
        while True:
            data = monitor.process()
            if data:
                data['monitor'] = self.monitor_id
                r = self._post(data)
                if r.status_code != 200:
                    self.logger.warning('Non 200 status code')
                    self.logger.warning(r.status_code)
                    try:
                        self.logger.warning(r.text)
                    except:
                        self.logger.warning('no text')

    def _tail(self, monitor, pos=None):
        # get initial position (EOF)
        if pos is None:
            with open(monitor.logfile) as logfile:
                logfile.seek(0, 2)
                pos = logfile.tell()

        # tail file
        while True:
            with open(monitor.logfile) as logfile:
                logfile.seek(0, 2)
                eof = logfile.tell()
                if pos > eof:
                    self.logger.warning('logfile got shorter, this should not happen')
                    pos = eof
                logfile.seek(pos)
                lines = logfile.readlines()
                pos = logfile.tell()
                if lines:
                    for line in lines:
                        monitor.queue.put(line.strip())
                else:
                    time.sleep(.1)

    def _drop_privileges(self):
        '''
        Drop superuser privileges from a thread
        '''
        if os.getuid() != 0:
            return
        running_uid = pwd.getpwnam(self.user).pw_uid
        running_gid = grp.getgrnam(self.group).gr_gid
        os.setgroups([])
        os.setgid(running_gid)
        os.setuid(running_uid)

