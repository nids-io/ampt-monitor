import sys
import logging
import argparse
import importlib

from configobj import ConfigObj

from ..amptmonitor import AmptMonitor


DEFAULTS = {
    'config': '/etc/ampt-monitor.conf',
    'monitor_section': 'monitors',
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

    config = ConfigObj(args.config)

    # List of loaded and configured monitor modules to pass to AmptMonitor
    loaded_monitors = []

    # Dictionary of monitor configs
    conf_monitors = config[DEFAULTS['monitor_section']]
    # List of monitor modules to load
    modules = conf_monitors.keys()

    # Dynamically load and configure monitor modules 
    for mod in modules:
        module_name = 'ampt_monitor_%s' % mod
        try:
            m = importlib.import_module(module_name)
            print('Loaded %s plugin from %s module' % (mod, module_name))
        except ImportError as e:
            errmsg = ('Monitor type %s specified in configuration but could '
                      'not be loaded (error: %s)' % (mod, e))
            print(errmsg)
    sys.exit()

    for monitor in config:
        if monitor == 'global':
            continue
        settings = config[monitor]
        if settings['type'] == 'suri':
            loaded_monitors.append(SuriAmptMonitor(
                int(settings['sid']),
                settings['path'],
                (config['global'].get('utc_offset') or 0)
            ))
    ampt_monitor = AmptMonitor(
        loaded_monitors,
        config['logfile'],
        (args.loglevel or config.get('loglevel') or DEFAULTS['loglevel']),
        (args.user or config.get('user') or DEFAULTS['user']),
        (args.group or config.get('group') or DEFAULTS['group']),
        config['url'],
        config['monitor_id']
    )

    ampt_monitor.run()

