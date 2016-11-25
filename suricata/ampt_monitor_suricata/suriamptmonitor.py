import multiprocessing
from dateutil import parser
from datetime import timedelta

import ujson


class SuriAmptMonitor(object):
    def __init__(self, sid, logfile, offset):
        self.sid = sid
        self.logfile = logfile
        self.queue = multiprocessing.Queue()
        self.offset = int(offset)

    def process(self):
        log = self.queue.get()
        if str(self.sid) not in log:
            # Move on before JSON parsing
            return
        log = ujson.loads(log)
        if log.get('event_type') != 'alert':
            # Move on if not an alert event
            return
        if log.get('alert').get('signature_id') != self.sid:
            # Move on if not healthcheck alert
            return

        fields = {
            'alert_time': (parser.parse(log.get('timestamp'))
                           + timedelta(hours=self.offset)).isoformat(),
            'src_addr': log.get('src_ip'),
            'src_port': log.get('src_port'),
            'dest_addr': log.get('dest_ip'),
            'dest_port': log.get('dest_port'),
            'protocol': (log.get('proto') or '').lower(),
        }
        return fields

