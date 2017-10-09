'''
AMPT Monitor plugin base class

'''
import abc
import socket
import logging

from .. import __application_name__                         


class AMPTPluginBase(abc.ABC):
    '''
    Abstract base class for AMPT Monitor plugins.

    '''

    def __init__(self, monitor_id, queue, rule_id, utc_offset=None, **kwargs):
        '''Set up the plugin and provide configuration.

        :param monitor_id: Integer specifying the monitor's ID in the AMPT
                           Manager
        :param queue:      Queue object to load with log events for the parent
                           process
        :param rule_id:    Integer specifying the health check probe rule ID,
                           typically the SID of the rule output by the AMPT
                           Generator
        :param utc_offset: Signed integer specifying a timezone offset
                           adjustment from UTC that should be applied to event
                           log timestamps prior to returning them to the main
                           AMPT Monitor process. This is necessary in cases
                           that the sensor logs contain timestamps in the
                           local timezone, if that timezone is not UTC.
                           Different sensors on the same monitor host may have
                           differing timezones in effect.

        '''
        self.logger = logging.getLogger(__application_name__)
        self.queue = queue

        self.monitor_id = monitor_id
        self.hostname = socket.getfqdn()
        self.rule_id = int(rule_id)
        self.utc_offset = int(utc_offset)

        self.parsed_event = {
            'monitor': self.monitor_id,
            'hostname': self.hostname,
        }

    @abc.abstractmethod
    def run():
        '''Run the plugin to start monitor loop.

        Plugins override this method to provide their implementation.
        '''
