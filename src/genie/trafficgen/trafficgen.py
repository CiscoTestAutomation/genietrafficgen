'''
Connection Implementation class for traffic generator device
'''

# pyATS
from ats.connections import BaseConnection


class TrafficGen(BaseConnection):

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
