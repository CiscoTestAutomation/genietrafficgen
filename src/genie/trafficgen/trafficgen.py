'''
Connection Implementation class for traffic generator device
'''
import warnings

# pyATS
from pyats.connections import BaseConnection

from genie import trafficgen
from genie.abstract import Lookup


class TrafficGen(BaseConnection):

    def __new__(cls, device, *args, **kwargs):
        if '.'.join([cls.__module__, cls.__name__]) == \
                'genie.trafficgen.trafficgen.TrafficGen':
            tgen_abstract = Lookup.from_device(
                device, packages={'tgn': trafficgen}, default_tokens=['os'])
            new_cls = tgen_abstract.tgn.TrafficGen
            return super().__new__(new_cls)
        else:
            return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        '''__init__ instantiates a single connection instance.'''
        # BaseConnection
        super().__init__(*args, **kwargs)
        self._is_connected = False

    @property
    def connected(self):
        '''Is traffic generator device connected'''
        return self._is_connected

    def connect(self):
        '''Connect to traffic generator device'''
        raise NotImplementedError

    def disconnect(self):
        '''Disconnect from traffic generator device'''
        raise NotImplementedError

    def load_configuration(self):
        '''Load static configuration file onto traffic generator device'''
        raise NotImplementedError

    def start_all_protocols(self):
        '''Start all protocols on traffic generator device'''
        raise NotImplementedError

    def apply_traffic(self):
        '''Apply L2/L3 traffic on traffic generator device'''
        raise NotImplementedError

    def send_arp(self):
        '''Send ARP to all interfaces from traffic generator device'''
        raise NotImplementedError

    def send_ns(self):
        '''Send NS to all interfaces from traffic generator device'''
        raise NotImplementedError

    def start_traffic(self):
        '''Start traffic on traffic generator device'''
        raise NotImplementedError

    def stop_traffic(self):
        '''Stop traffic on traffic generator device'''
        raise NotImplementedError

    def clear_statistics(self):
        '''Clear all traffic, port, protocol statistics on traffic generator device'''
        raise NotImplementedError

    def check_traffic_loss(self):
        '''Check for traffic loss on a traffic stream configured on traffic generator device'''
        raise NotImplementedError

    def create_traffic_profile(self):
        '''Create traffic profile of configured streams on traffic generator device'''

        raise NotImplementedError

    def compare_traffic_profile(self):
        '''Compare two traffic generator device traffic profiles'''
        raise NotImplementedError
