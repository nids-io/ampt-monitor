import sys
import logging

from configobj import ConfigObj

from ..amptmonitor import AmptMonitor


logging.basicConfig()

def main():
    conf = ConfigObj('/etc/ampt-monitor.cnf')
    monitors = []
    types = [conf[a].get('type') for a in conf]
    if 'suri' in types:
        try:
            from ampt_monitor_suricata.suriamptmonitor import SuriAmptMonitor
        except:
            errmsg = 'Suricata module specified in config but module is not installed'
            sys.exit(errmsg)

    for monitor in conf:
        if monitor == 'global':
            continue
        settings = conf[monitor]
        if settings['type'] == 'suri':
            monitors.append(SuriAmptMonitor(
                int(settings['sid']),
                settings['path'],
                (conf['global'].get('utc_offset') or 0)
            ))
    monitor = AmptMonitor(
        monitors,
        conf['global']['logfile'],
        (conf['global'].get("loglevel") or "DEBUG"),
        conf['global']['url'],
        conf['global']['monitor_id']
    )

    monitor.run()

if __name__ == "__main__":
    main()
