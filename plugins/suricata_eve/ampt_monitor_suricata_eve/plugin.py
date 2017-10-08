'''
AMPT Monitor plugin for Suricata EVE log files.

This plugin reads the Suricata EVE event log (a JSON event format file)
looking for events related to AMPT healthcheck probes. Events are identified
using the specified rule_id matching the SID of the AMPT rule in the sensor
ruleset.

'''
import time
import logging
from dateutil import parser
from datetime import timedelta

import ujson

from ampt_monitor.plugin.base import AMPTPluginBase


# Default sleep period between polling logs from file (in seconds)
LOOP_INTERVAL = 3

class SuricataEveAMPTMonitor(AMPTPluginBase):
    '''
    AMPT Monitor plugin for Suricata EVE JSON alert logs

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

        self.logger.debug('XXX In plugin run() method')
        for eve_log in self._tail_logfile(self.path):
            parsed_event = self._parse_log(eve_log)
            if parsed_event is not None:
                self.logger.debug('XXX prepared log event for core process: %s',
                    parsed_event)
                self.queue.put(parsed_event)

    def _tail_logfile(self, path, pos=None):
        '''
        Tail the specified log file and return candidate log lines for
        processing.

        '''
        self.logger.debug('XXX beginning to tail log file (%s)', self.path)
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
                    self.logger.warning('logfile got shorter, this should not happen')
                    pos = eof
                logfile.seek(pos)
                lines = logfile.readlines()
                self.logger.debug('XXX fetched %s lines from log file', len(lines))
                pos = logfile.tell()
                if lines:
                    self.logger.debug('XXX new lines from log file were acquired')
                    for line in lines:
                        self.logger.debug('XXX processing new line from log file')
                        # Pre-filter for logs containing the healthcheck rule ID
                        if str(self.rule_id) in line:
                            self.logger.debug('XXX found log line with target rule_id %s: %s', self.rule_id, line.strip())
                            yield(line.strip())
                else:
                    self.logger.debug('XXX no new lines from log file fetched')
                    time.sleep(self.interval)

    ### XXX below here original/only contents of process()
    def _parse_log(self, log):
        '''
        Parse received EVE log event into dictionary and return to caller.

        '''
        try:
            log = ujson.loads(log)
        except ValueError as e:
            msg = 'error parsing input as JSON data (library output: %s)'
            self.logger.warning(msg, e)
            self.logger.debug('faulty input data: %s', str(log))
            return
        self.logger.debug('XXX log from json: %s', log)
        if log['event_type'] != 'alert':
            # Move on if not an alert event
            self.logger.debug('XXX bailing cuz event_type is not alert')
            self.logger.debug('XXX event_type is: %s', log['event_type'])
            return
        if log['alert']['signature_id'] != self.rule_id:
            # Move on if not healthcheck alert
            self.logger.debug('XXX bailing cuz signature_id is not %s', self.rule_id)
            self.logger.debug('XXX log-alert-signature_id is: %s (%s)',
                              log['alert']['signature_id'],
                              type(log['alert']['signature_id']))
            self.logger.debug('XXX self-rule_id is: %s (%s)',
                              self.rule_id, type(self.rule_id))
            return

        self.logger.debug('XXX preparing event dictionary')
        _timestamp = log['timestamp']
        if self.utc_offset is not None:
            _timestamp = (parser.parse(log['timestamp'])
                         - timedelta(hours=self.utc_offset)).isoformat(timespec='seconds')
        parsed_event = {
            'monitor': self.monitor_id,
            'alert_time': _timestamp,
            'src_addr': log.get('src_ip'),
            'src_port': log.get('src_port'),
            'dest_addr': log.get('dest_ip'),
            'dest_port': log.get('dest_port'),
            'protocol': (log.get('proto') or '').lower(),
        }
        self.logger.debug('XXX returning event dictionary: %s', parsed_event)
        return parsed_event

