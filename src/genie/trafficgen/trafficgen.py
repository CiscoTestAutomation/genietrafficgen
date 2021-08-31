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

    def configure_dhcpv4_request(self):
        '''Send DHCPv4 REQUEST packet from traffic generator device'''
        raise NotImplementedError

    def configure_dhcpv4_reply(self):
        '''Send DHCPv4 REPLY packet from traffic generator device'''
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

    # Multicast APIs
    def create_multicast_group(self, groupip, inc_steps='0.0.0.0',
                               ip_prefix_len=32, group_nums=1):
        '''Create multicast group pool
           Args:
             groupip ('str'): group ipv4/ipv6 address
             inc_steps ('str'): Used to increment group address
             ip_prefix_len ('int'): Defaults to 32 for IPv4 and 128 for IPv6.
             group_nums ('int'): number of groups
           Returns:
             multicast group pool handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def delete_multicast_group(self, group_handler):
        '''delete multicast group pool
           Args:
             group_handler ('obj'): multicast group pool handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def create_multicast_source(self, sourceip, inc_steps='0.0.0.0',
                                ip_prefix_len=32, source_nums=1):
        '''Create multicast source pool
           Args:
             sourceip ('str'): source ipv4/ipv6 address
             inc_steps ('str'): Used to increment source address
             ip_prefix_len ('int'): Defaults to 32 for IPv4 and 128 for IPv6.
             source_nums ('int'): number of sources
           Returns:
             multicast source pool handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def delete_multicast_source(self, source_handler):
        '''delete multicast source pool
           Args:
             source_handler ('obj'): multicast source pool handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    # IGMP APIs
    def create_igmp_client(self, interface, clientip, version, vlanid=0):
        '''Create IGMP Client
           Args:
             interface ('str'): interface name
             clientip ('str'): ip address
             version ('int'): 2 or 3
             vlanid ('int'): vlan id
           Returns:
             igmp client handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def delete_igmp_client(self, client_handler):
        '''Delete IGMP Client
           Args:
             client_handler ('obj'): IGMP Client handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def igmp_client_add_group(self, client_handler,
                              group_handler,
                              source_handler=None,
                              filter_mode='N/A'):
        '''IGMP Client add group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is None, means (*, g)
             filter_mode ('str'): include | exclude | N/A (by default)

             for v3 (*,g) which is (0.0.0.0, g)-exclude, the source_handler
             should be None, filter_mode should be exclude
           Returns:
             group membership handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def igmp_client_modify_group_filter_mode(self, client_handler,
                                             handler, filter_mode):
        '''IGMP Client modify group member filter mode, Only IGMP v3
           client is supported
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
             filter_mode: include | exclude
           Returns:
             Updated Group membership handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def igmp_client_del_group(self, client_handler, handler):
        '''IGMP Client delete group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def igmp_client_control(self, interface, client_handler, mode):
        '''IGMP Client protocol control
           Args:
             interface ('str'): interface name
             client_handler: IGMP Client handler
             mode ('mode'):
                start: start the client with sending igmp join message
                stop: stop the client with sending igmp leave message
                restart: restart the client
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError
