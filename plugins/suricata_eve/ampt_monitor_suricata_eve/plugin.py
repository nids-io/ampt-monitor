'''
AMPT Monitor plugin for Suricata EVE log files.

This plugin reads the Suricata EVE event log looking for events related to
AMPT healthcheck probes. Events are identified using the specified rule_id
matching the SID of the AMPT rule in the sensor ruleset.

'''
import time
import dateutil.parser
from datetime import timedelta

import pytz
import ujson

from ampt_monitor.plugin.base import AMPTPlugin


UTC = pytz.utc

# Default sleep period between polling logs from file (in seconds)
LOOP_INTERVAL = 3
# GID 1 == text rules
GENERATOR_TEXT_RULE = 1

class SuricataEveAMPTMonitor(AMPTPlugin):
    '''
    AMPT Monitor plugin for Suricata EVE JSON alert logs

    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.interval = int(self.config.get('interval', LOOP_INTERVAL))

    def run(self):
        'Run plugin main loop'

        self.logger.debug('executing plugin run() method...')
        for eve_log in self._tail_logfile(self.config['path']):
            parsed_event = self._parse_log(eve_log)
            if parsed_event is not None:
                self.logger.info('extracted new healthcheck log message '
                                 'from %s', self.config['path'])
                self.logger.debug('parsed log event for core process: %s',
                    parsed_event)
                self.queue.put(parsed_event)

    def _tail_logfile(self, path, pos=None):
        '''
        Tail the specified log file and return candidate log lines for
        processing.

        '''
        self.logger.debug('beginning to tail log file %s', self.config['path'])
        if pos is None:
            with open(self.config['path']) as logfile:
                logfile.seek(0, 2)
                pos = logfile.tell()

        # Tail the logfile
        while True:
            with open(self.config['path']) as logfile:
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
                        if str(self.config['rule_id']) in line:
                            self.logger.debug('log contains target '
                                              'rule_id %s: %s',
                                              self.config['rule_id'], line.strip())
                            yield(line.strip())
                else:
                    self.logger.debug('no new lines acquired from log file')
                    time.sleep(self.interval)

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
        self.logger.debug('log data parsed from JSON: %s', log)
        if log['event_type'] != 'alert':
            self.logger.debug('skipping non-alert event type (%s)',
                              log['event_type'])
            return
        if (log['alert']['signature_id'] != self.config['rule_id']
            and log['alert']['gid'] != GENERATOR_TEXT_RULE):

            # Move on if not healthcheck alert
            self.logger.debug('skipping non-healthcheck alert (%s)'
                              ':'.join([log['alert']['gid'],
                                        log['alert']['signature_id']]))
            return

        # Parse EVE timestamp
        _ts = dateutil.parser.parse(log['timestamp'])
        # Normalize to UTC and drop TZ info from timestamp
        _utc_ts = _ts.astimezone(UTC).replace(tzinfo=None)
        # Format to ISO 8601 with seconds precision
        _final_ts = _utc_ts.isoformat(timespec='seconds')

        self.parsed_event.update({
            'alert_time': _final_ts,
            'src_addr': log.get('src_ip'),
            'src_port': log.get('src_port'),
            'dest_addr': log.get('dest_ip'),
            'dest_port': log.get('dest_port'),
            'protocol': (log.get('proto') or '').lower(),
        })
        self.logger.debug('returning event dictionary from parsed log data: %s',
                          self.parsed_event)
        return self.parsed_event

