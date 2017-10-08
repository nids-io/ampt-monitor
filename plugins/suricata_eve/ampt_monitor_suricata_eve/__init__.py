'''
AMPT Monitor plugin for Suricata EVE logs

'''
# XXX maybe all of this just needs to be moved into the main plugin
# module/class
# The class docstring could also be used as the documentation for the plugin
# and can show config options, etc.
__plugin_name__ = 'suricata_eve'
__version__ = '0.2.6'
# XXX intention is to expose this via the plugin class so it can be set as the
# the multiprocessing.Process name argument
__proc_name__ = 'SuricataEve'
__author__  = [
    'Darren Spruell <phatbuckett@gmail.com>',
    'Nate Falke <nate.falke@gmail.com>',
]

