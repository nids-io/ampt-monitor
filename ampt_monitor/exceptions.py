'''
AMPT monitor exceptions

'''
class AMPTMonitorException(Exception):
    'Package base exception class'


class NoPluginError(AMPTMonitorException):
    'Error raised when no monitor plugin(s) could be loaded.'

