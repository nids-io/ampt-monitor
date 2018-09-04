'''
AMPT Monitor plugin base class

'''
from abc import ABC, abstractmethod
import socket
import logging

from .. import __application_name__


# Protocol field value to use in case of missing protocol field in logs
LOG_PROTO_UNSPECIFIED = 'unspecified'

class AMPTPlugin(ABC):
    '''
    Abstract base class for AMPT Monitor plugins.

    '''
    def __init__(self, monitor_id, queue, plugin_name, config):
        '''Set up the plugin and provide configuration.

        :param monitor_id:  Integer specifying the monitor's ID in the AMPT
                            Manager
        :param queue:       Queue object to load with log events for the parent
                            process
        :param plugin_name: Plugin name as passed in from AMPT Monitor core
        :param config:      Plugin configuration dictionary consisting of
                            remaining options from config file

        '''
        self.logger = logging.getLogger(__application_name__)

        self.monitor_id = int(monitor_id)
        self.queue = queue
        self.plugin_name = plugin_name
        self.config = config
        self.hostname = socket.getfqdn()

        # Prepare skeleton of parsed event using elements sent in every event
        # back to manager. The plugin extracts and adds additional elements.
        self.parsed_event = {
            'monitor': self.monitor_id,
            'hostname': self.hostname,
            'plugin_name': self.plugin_name,
        }
        # Setting option in plugin config primes the value expected by the
        # manager in the event.
        if self.config.get('no_log_protocol'):
            self.parsed_event.update({'protocol': LOG_PROTO_UNSPECIFIED})

    @abstractmethod
    def run():
        '''Run the plugin to start monitor loop.

        Plugins override this method to provide their implementation.
        '''
