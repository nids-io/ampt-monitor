'''
AMPT Monitor plugin for Zeek signature logs

'''
import pkg_resources


# XXX maybe all of this just needs to be moved into the main plugin
# module/class
# The class docstring could also be used as the documentation for the plugin
# and can show config options, etc.
__version__ = pkg_resources.get_distribution('ampt_monitor_zeek').version
