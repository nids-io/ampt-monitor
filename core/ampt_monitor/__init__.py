'''
AMPT Monitor

'''
import pkg_resources


__application_name__ = 'ampt-monitor'
__application_title__ = 'AMPT Monitor'
__url__ = 'https://github.com/nids-io/ampt-monitor'
__version__ = pkg_resources.get_distribution('ampt_monitor').version

def get_ampt_version(with_plugins=False):
    '''Return software version info.

    :param with_plugins: whether to include information about installed
                         monitor plugins
    :return:             version info string

    '''
    version_core = u'{} {}'.format(__application_title__, __version__)
    if with_plugins:
        import stevedore
        mgr = stevedore.ExtensionManager(namespace='ampt_monitor.plugin',
                                         invoke_on_load=False)
        plugin_info = [version_core]
        if len(mgr.extensions):
            from tabulate import tabulate
            #plugin_info.append('[Installed plugins]')
            plugin_entry = []
            for p in mgr.list_entry_points():
                plug_ver = pkg_resources.get_distribution(p.module_name.split('.')[0]).version
                plugin_entry.append(['', '[plugin]', p.name, plug_ver, p.attrs[0], p.module_name])
            plugin_info.append(tabulate(plugin_entry, tablefmt='plain'))
        return '\n'.join(plugin_info)
    else:
        return version_core
