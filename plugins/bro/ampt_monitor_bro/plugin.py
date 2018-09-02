'''
AMPT Monitor plugin for Bro signature log files.

This plugin reads the Bro signature log looking for events related to AMPT
healthcheck probes. Events are identified using the specified sig_id matching
the signature ID of the AMPT rule in the Bro ruleset.

'''
import re
import logging
import dateutil.parser
from time import sleep
from datetime import timedelta  # XXX probably kill

import pytz  # XXX probably kill

from ampt_monitor.plugin.base import AMPTPluginBase


UTC = pytz.utc  # XXX probably kill

# Default sleep period between polling logs from file (in seconds)
LOOP_INTERVAL = 3

# Regex to match Bro signature logs
RE_SIG_LOG = re.compile(r'(?P<ts>\d+\.\d+)\s\S+\s(?P<src_addr>\S+)\s(?P<src_port>\d{1,5})\s(?P<dst_addr>\S+)\s(?P<dst_port>\d{1,5})')

class BroAMPTMonitor(AMPTPluginBase):
    '''
    AMPT Monitor plugin for Bro signature logs

    '''
    def __init__(self, path, interval=LOOP_INTERVAL, **kwargs):
        # Plugin is a file reader, so expects a "path" configuration option to
        # be passed in
        self.path = path
        # Allow configuration to specify an interval at which the file tailer
        # collects new log lines
        self.interval = int(interval)
        super().__init__(**kwargs)

    def run(self):
        'Run plugin main loop'

        self.logger.debug('executing plugin run() method...')
        for bro_log in self._tail_logfile(self.path):
            parsed_event = self._parse_log(bro_log)
            if parsed_event is not None:
                self.logger.info('extracted new healthcheck log message '
                                 'from %s', self.path)
                self.logger.debug('parsed log event for core process: %s',
                    parsed_event)
                self.queue.put(parsed_event)

    def _tail_logfile(self, path, pos=None):
        '''
        Tail the specified log file and return candidate log lines for
        processing.

        '''
        self.logger.debug('beginning to tail log file %s', self.path)
        if pos is None:
            with open(self.path) as logfile:
                logfile.seek(0, 2)
                pos = logfile.tell()

        # Tail the logfile
        while True:
            with open(self.path) as logfile:
                logfile.seek(0, 2)
                eof = logfile.tell()
                if pos > eof:
                    self.logger.warning('logfile got shorter, this should '
                                        'not happen')
                    pos = eof
                logfile.seek(pos)
                lines = logfile.readlines()
                if lines:
                    self.logger.debug('acquired %d new %s from log file',
                                      len(lines),
                                      'line' if len(lines) == 1 else 'lines')
                pos = logfile.tell()
                if lines:
                    for line in lines:
                        self.logger.debug('preprocessing new line from '
                                          'log file')
                        # Pre-filter for logs containing the healthcheck
                        # rule ID
                        if str(self.sig_id) in line:
                            self.logger.debug('log contains target '
                                              'sig_id %s: %s',
                                              self.sig_id, line.strip())
                            yield(line.strip())
                else:
                    self.logger.debug('no new lines acquired from log file')
                    sleep(self.interval)

    def _parse_log(self, log):
        '''
        Parse received Bro log event into dictionary and return to caller.

        '''
        try:
            log = RE_SIG_LOG.match(log).group_dict()
        except ValueError as e:
            msg = 'error parsing input as delimited data (library output: %s)'
            self.logger.warning(msg, e)
            self.logger.debug('faulty input data: %s', str(log))
            return
        self.logger.debug('data parsed from log: %s', log)

        # Parse Bro timestamp
        _timestamp = datetime.datetime.utcfromtimestamp(log['ts'])
        # Format to ISO 8601 with seconds precision
        _timestamp = _timestamp.isoformat(timespec='seconds')

        # XXX 2018-09-02 DRS: Default Bro signature logs do not currently
        # contain the IP protocol, so we work around this by pretending that all
	# packets are TCP. For the time being (if this matters), we need to
	# recommend that all health check probes to segments monitored by Snort
	# are configured as TCP. May be able to fix this in future by setting a
	# customer logger for the signatures that also writes out the protocol
	# field. If it doesn't matter, disregard, because the dict builder below
	# appears to treat the protocol as optional and passes an empty string.
        self.parsed_event.update({
            'alert_time': _timestamp,
            'src_addr': log.get('src_addr'),
            'src_port': log.get('src_port'),
            'dest_addr': log.get('dst_addr'),
            'dest_port': log.get('dst_port'),
            'protocol': (log.get('proto') or '').lower(),
        })
        self.logger.debug('returning event dictionary from parsed log data: %s',
                          self.parsed_event)
        return self.parsed_event

