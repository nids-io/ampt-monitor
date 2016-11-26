import sys
import logging
import argparse

from configobj import ConfigObj

from ..amptmonitor import AmptMonitor


DEFAULTS = {
    'config': '/etc/ampt-monitor.conf',
    'loglevel': 'warning',
    'user': 'ampt',
    'group': 'ampt',
}
LOGLEVEL_CHOICES = ['debug', 'info', 'warning', 'error', 'critical']

logging.basicConfig()

def main():
    description = 'Event log monitor utility for the AMPT passive tools monitor'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-c', '--config', default=DEFAULTS['config'],
                        help='configuration file path (default: %(default)s)')
    parser.add_argument('-l', '--loglevel', choices=LOGLEVEL_CHOICES,
                            help='set logging verbosity level '
                                 '(default: "%s" or from config file)' % DEFAULTS['loglevel'])
    parser.add_argument('-u', '--user', help='user as which to run ampt-monitor '
                                 '(default: "%s" or from config file)' % DEFAULTS['user'])
    parser.add_argument('-g', '--group', help='group as which to run ampt-monitor '
                                 '(default: "%s" or from config file)' % DEFAULTS['group'])
    args = parser.parse_args()

    conf = ConfigObj(args.config)
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
        (args.loglevel or conf['global'].get('loglevel') or DEFAULTS['loglevel']),
        (args.user or conf['global'].get('user') or DEFAULTS['user']),
        (args.group or conf['global'].get('group') or DEFAULTS['group']),
        conf['global']['url'],
        conf['global']['monitor_id']
    )

    monitor.run()

