'''
AMPT Monitor plugin for Bro signature log files.

This plugin reads the Bro signature log looking for events related to AMPT
healthcheck probes. Events are identified using the specified sig_id matching
the signature ID of the AMPT rule in the Bro ruleset.

'''
import re
import dateutil.parser
from time import sleep
from datetime import datetime

from ampt_monitor.plugin.base import AMPTPlugin


# Default sleep period between polling logs from file (in seconds)
LOOP_INTERVAL = 3

# Regex to extract fields from Bro signature logs
RE_SIG_LOG = re.compile(r'''(?P<ts>\d+\.\d+)\s
                            \S+\s
                            (?P<src_addr>\S+)\s
                            (?P<src_port>\d{1,5})\s
                            (?P<dst_addr>\S+)\s
                            (?P<dst_port>\d{1,5})''', re.X)

class BroAMPTMonitor(AMPTPlugin):
    '''
    AMPT Monitor plugin for Bro signature logs

    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.interval = int(self.config.get('interval', LOOP_INTERVAL))

    def run(self):
        'Run plugin main loop'

        self.logger.debug('executing plugin run() method...')
        for bro_log in self._tail_logfile(self.config['path']):
            parsed_event = self._parse_log(bro_log)
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
                        if str(self.config['sig_id']) in line:
                            self.logger.debug('log contains target '
                                              'sig_id %s: %s',
                                              self.config['sig_id'], line.strip())
                            yield(line.strip())
                else:
                    self.logger.debug('no new lines acquired from log file')
                    sleep(self.interval)

    def _parse_log(self, log):
        '''
        Parse received Bro log event into dictionary and return to caller.

        '''
        try:
            log = RE_SIG_LOG.match(log).groupdict()
        except ValueError as e:
            msg = 'error parsing input as delimited data (library output: %s)'
            self.logger.warning(msg, e)
            self.logger.debug('faulty input data: %s', str(log))
            return
        self.logger.debug('data parsed from log: %s', log)

        # Parse Bro timestamp
        _ts = datetime.utcfromtimestamp(float(log['ts']))
        # Format to ISO 8601 with seconds precision
        _final_ts = _ts.isoformat(timespec='seconds')

        # Default Bro signature logs do not currently contain the IP protocol,
        # so base plugin class will supply appropriate value and handle when
        # the no_log_protocol flag is set in plugin config.
        # Also note that the ports must be treated as integers since the regex
        # parser sets them as strings by default.
        self.parsed_event.update({
            'alert_time': _final_ts,
            'src_addr': log.get('src_addr'),
            'src_port': int(log.get('src_port')),
            'dest_addr': log.get('dst_addr'),
            'dest_port': int(log.get('dst_port')),
        })
        self.logger.debug('returning event dictionary from parsed log data: %s',
                          self.parsed_event)
        return self.parsed_event

