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
            if hasattr(device, 'platform') and device.platform:
                tgen_abstract = Lookup.from_device(device, packages={'tgn': trafficgen}, default_tokens=['os', 'platform'])
                try:
                  new_cls = getattr(tgen_abstract.tgn, device.platform).TrafficGen
                except LookupError:
                  new_cls = tgen_abstract.tgn.TrafficGen
            else:
                tgen_abstract = Lookup.from_device(device, packages={'tgn': trafficgen}, default_tokens=['os'])
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

    def configure_dhcpv4_request(self, interface, mac_src, requested_ip, xid=0,
                                 transmit_mode='single_burst', pkts_per_burst=1, pps=100):
        '''Configure DHCPv4 REQUEST packet from traffic generator device
           Args:
             interface ('int'): port to configure stream
             mac_src ('str'): source mac address
             requested_ip ('str'): requested ip address
             xid ('int', optional): transaction id, default 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), default single_burst
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_dhcpv4_reply(self, interface, mac_src, ip_src, assigned_ip,
                               lease_time, xid=0, transmit_mode='single_burst',
                               pkts_per_burst=1, pps=100):
        '''Configure DHCPv4 REPLY packet from traffic generator device
           Args:
             interface ('int'): port to configure stream
             mac_src ('str'): source mac address
             ip_src ('str'): source ip address
             assigned_ip ('str'): ip assigned by dhcp server
             lease_time ('int'): assigned ip lease time
             xid ('int', optional): transaction id, default 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), default single_burst
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_dhcpv6_request(self, interface, src_mac, requested_ip,
                            cid=None, sid=None,
                            vlan_id=0, xid=0,
                            transmit_mode='single_burst',
                            pkts_per_burst=1, pps=100):
        '''Send DHCPv6 REQUEST packet from traffic generator device
          Args:
            interface ('str'): interface to send packets on
            src_mac ('str'): source mac address
            requested_ip ('str'): requested ip address
            cid ('str', optional): client id, default None
            sid ('str', optional): server id, default None
            vlan_id ('int', optional): vlan identifier, default 0
            xid ('int', optional): transaction id, default 0
            transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), default single_burst
            pkts_per_burst ('int', optional): packets per burst, default 1
            pps ('int', optional): packets per second, default 100
          Returns:
            None
          Raises:
            GenieTgnError
        '''

    def configure_arp_request(self, port, mac_src, ip_src, ip_dst, frame_size=60,
                              vlan_id=0, transmit_mode='single_burst',
                              pkts_per_burst=1, pps=100):
        '''Configure an ARP request from traffic generator device
           Args:
             port ('int'): port to configure stream
             mac_src ('str'): source mac address
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             frame_size ('int', optional): frame size, default 60
             vlan_id ('int', optional): vlad id, default 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_dhcpv6_reply(self, interface, src_mac, src_ip, assigned_ip, lease_time,
                          cid=None, sid=None, vlan_id=0, xid=0,
                          transmit_mode='single_burst',
                          pkts_per_burst=1, pps=100):
        '''Send DHCPv6 REPLY packet from traffic generator device
          Args:
            interface ('str'): interface to send packets on
            assigned_ip ('str'): ip assigned by dhcp server
            src_mac ('str'): source mac address
            src_ip ('str'): source ip address
            lease_time ('int'): assigned ip lease time
            cid ('str', optional): client id, default None
            sid ('str', optional): server id, default None
            vlan_id ('int', optional): vlan identifier, default 0
            xid ('int', optional): transaction id, default 0
            transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), default single_burst
            pkts_per_burst ('int', optional): packets per burst, default 1
            pps ('int', optional): packets per second, default 100
            Returns:
                None
            Raises:
                GenieTgnError
        '''

    def configure_garp(self, port, mac_src, ip, frame_size=60,
                       vlan_id=0, transmit_mode='single_burst',
                       pkts_per_burst=1, pps=100):
        '''Configure a gratuitous ARP stream from traffic generator device
           Args:
             port ('int'): port to configure stream
             mac_src ('str'): source mac address
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             frame_size ('int', optional): frame size, default 60
             vlan_id ('int', optional): vlad id, default 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_acd(self, port, mac_src, ip_dst, frame_size=60,
                      vlan_id=0, transmit_mode='single_burst',
                      pkts_per_burst=1, pps=100):
        '''Configure an address conflict detection stream from traffic generator device
           Args:
             port ('int'): port to configure stream
             mac_src ('str'): source mac address
             ip_dst ('str'): destination ip address
             frame_size ('int', optional): frame size, default 60
             vlan_id ('int', optional): vlad id, default 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_ns(self, interface, mac_src, ip_src, ip_dst, hop_limit=255,
                     length_mode='auto', vlan_id=0, transmit_mode='single_burst',
                     pkts_per_burst=1, pps=100):
        '''Configure an NS stream from traffic generator device
           Args:
             interface ('int'): interface to configure stream
             mac_src ('str'): source mac address
             ip_src ('str'): source IPv6 address
             ip_dst ('str'): destination IPv6 address
             hop_limit ('int', optional): packet hop limit, defaults to 255
             length_mode ('str', optional): length mode, defaults to 'auto'
             vlan_id ('int', optional): vlan id, defaults to 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_na(self, interface, mac_src, ip_src, ip_dst, solicited=True,
                     hop_limit=255, length_mode='auto', vlan_id=0,
                     transmit_mode='single_burst', pkts_per_burst=1, pps=100):
        '''Configure an NA stream from traffic generator device
           Args:
             interface ('int'): interface to configure stream
             mac_src ('str'): source mac address
             ip_src ('str'): source IPv6 address
             ip_dst ('str'): destination IPv6 address
             solicited ('bool', optional), flag for solicited/unsolicited NA packet, defaults to True
             hop_limit ('int', optional): packet hop limit, defaults to 255
             length_mode ('str', optional): length mode, defaults to 'auto'
             vlan_id ('int', optional): vlan id, defaults to 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_dad(self, interface, mac_src, ip_dst, hop_limit=255,
                      length_mode='auto', vlan_id=0, transmit_mode='single_burst',
                      pkts_per_burst=1, pps=100):
        '''Configure a DAD stream from traffic generator device
           Args:
             interface ('int'): interface to configure stream
             mac_src ('str'): source mac address
             ip_dst ('str'): destination IPv6 address
             hop_limit ('int', optional): packet hop limit, defaults to 255
             length_mode ('str', optional): length mode, defaults to 'auto'
             vlan_id ('int', optional): vlan id, defaults to 0
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_ipv4_data_traffic(self, interface, src_ip, dst_ip,
                                    l4_protocol, payload, transmit_mode='single_burst',
                                    pkts_per_burst=1, pps=100):
        '''Configure ipv4 data traffic stream
           Args:
             interface ('int'): interface to configure stream
             src_ip ('str'): ipv4 source address
             dst_ip ('str'): ipv4 destination address
             l4_protocol ('str'): can be one of ('tcp', 'udp')
             payload ('str'): data to be sent
             transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
             pkts_per_burst ('int', optional): packets per burst, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
        raise NotImplementedError

    def configure_ipv6_data_traffic(self, interface, src_ip, dst_ip,
                                    l4_protocol, payload, transmit_mode='single_burst',
                                    pkts_per_burst=1, pps=100):
        '''Configure ipv6 data traffic stream
           Args:
              interface ('int'): interface to configure stream
              src_ip ('str'): ipv6 source address
              dst_ip ('str'): ipv6 destination address
              l4_protocol ('str'): can be one of ('tcp', 'udp', 'icmp')
              payload ('str'): data to be sent
              transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), defaults to 'single_burst'
              pkts_per_burst ('int', optional): packets per burst, default 1
              pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             GenieTgnError
        '''
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

    # ========================================
    # APIs for sending packet
    # ========================================
    def send_rawip(self, interface, mac_src, mac_dst, ip_src, ip_dst,
                   vlanid=0, count=1, pps=100):
        '''Send rawip packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlanid ('int', optional): vlan id, default is 0
             count ('int', optional): send packets count, default is 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def send_rawipv6(self, interface, mac_src, mac_dst, ipv6_src, ipv6_dst,
                     vlanid=0, count=1, pps=100):
        '''Send rawipv6 packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, example aabb.bbcc.ccdd
             ipv6_src ('str'): source ipv6 address
             ipv6_dst ('str'): destination ipv6 address
             vlanid ('int', optional): vlan id, default = 0
             count ('int', optional): send packets count, default = 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def start_pkt_count_rawip(self, interface, mac_src, mac_dst,
                              ip_src, ip_dst, vlan_tag=0):
        '''Start packet count rawip
           Args:
             interface ('str' or 'list'): interface name
                                          or list of interface names
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan_tag ('int', optional): vlan tag, default is 0
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def start_pkt_count_rawipv6(self, interface, mac_src, mac_dst,
                                ipv6_src, ipv6_dst, vlan_tag=0):
        '''Start packet count rawip
           Args:
             interface ('str' or 'list'): interface name
                                          or list of interface names
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, example aabb.bbcc.ccdd
             ipv6_src ('str'): source ipv6 address
             ipv6_dst ('str'): destination ipv6 address
             vlan_tag ('int', optional): vlan id, default = 0
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def stop_pkt_count(self, interface):
        '''Stop ip packet count
           Args:
             interface ('str' or 'list'): interface name
                                  or list of interface names
                                  shall be same as passed in start_pkt_count
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def get_pkt_count(self, interface):
        '''Get ip packet count
           Args:
             interface ('str'): interface name
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def start_pkt_count_rawip_mcast(self, interface, mac_src,
                                    ip_src, ip_dst, vlan=0):
        '''Start ip packet count mcast
           Args:
             interface ('str' or 'list'): interface name
                                          or list of interface names
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan ('int', optional): vlan id, default is 0
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def send_rawip_mcast(self, interface, mac_src, ip_src, ip_dst,
                         vlan=0, count=1, pps=100):
        '''Start ip packet count mcast
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan ('int', optional): vlan id, default is 0
             count ('int', optional) : number of pkts send, default is 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def send_arp_request(self, interface, mac_src, ip_src, ip_target,
                         vlan_tag=0, count=1, pps=100):
        '''Send arp request packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_target ('str'): target ip address
             vlan_tag ('int', optional): vlan tag, default 0
             count ('int', optional): send packets count, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def send_ndp_ns(self, interface, mac_src, ip_src, ip_dst,
                    vlan_tag=0, count=1, pps=100):
        '''Send ndp neighbor solicitation packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan_tag ('int', optional): vlan tag, default 0
             count ('int', optional): send packets count, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def send_ndp_na(self, interface, mac_src, ip_src, ip_dst,
                    vlan_tag=0, count=1, pps=100):
        '''Send ndp neighbor solicitation packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan_tag ('int', optional): vlan tag, default 0
             count ('int', optional): send packets count, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    # ========================================
    # Multicast APIs
    # ========================================
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

    def igmp_client_del_group(self, client_handler, group_handler,
                              handler, source_handler='*'):
        '''IGMP Client delete group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is *, means (*, g)
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
           Returns:
             True
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

    # MLD APIs
    def create_mld_client(self, interface, clientip, version, vlanid=0):
        '''Create MLD Client
           Args:
             interface ('str'): interface name
             clientip ('str'): ip address
             version ('int'): v1 or v2
             vlanid ('int'): vlan id, default = 0
           Returns:
             mld client handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def delete_mld_client(self, client_handler):
        '''Delete MLD Client
           Args:
             client_handler ('obj'): MLD Client handler
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def mld_client_add_group(self, client_handler,
                             group_handler,
                             source_handler=None,
                             filter_mode='N/A'):
        '''MLD Client add group membership
           Args:
             client_handler ('obj'): MLD Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is None, means (*, g)
             filter_mode ('str'): include | exclude | N/A (by default)
           Returns:
             group membership handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def mld_client_modify_group_filter_mode(self, client_handler,
                                            handler, filter_mode):
        '''MLD Client modify group member filter mode, Only MLD v2
           client is supported
           Args:
             client_handler ('obj'): MLD Client handler
             handler ('obj'):
                Group membership handler created by mld_client_add_group
             filter_mode: include | exclude
           Returns:
             Updated Group membership handler
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def mld_client_del_group(self, client_handler, group_handler,
                             handler, source_handler='*'):
        '''MLD Client delete group membership
           Args:
             client_handler ('obj'): MLD Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is *, means (*, g)
             handler ('obj'):
                Group membership handler created by mld_client_add_group
           Returns:
             True
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def mld_client_control(self, interface, client_handler, mode):
        '''MLD Client protocol control
           Args:
             interface ('str'): interface name
             client_handler: MLD Client handler
             mode ('mode'):
                start: start the client with sending mld join message
                stop: stop the client with sending mld leave message
                restart: restart the client
           Returns:
             True/False
           Raises:
             NotImplementedError
        '''
        raise NotImplementedError

    def enable_subinterface_emulation(self, port, ip, mac):
        '''Enables subinterface emulation on the traffic generator's specified port
            Args:
             port ('int'): Traffic generator's port handle
             ip ('str'): ipv6 address
             mac ('str'): mac address
            Returns:
             Handle of subinterface group
        '''
        raise NotImplementedError

    def disable_subinterface_emulation(self, handle):
        '''Disables subinterface emulation on the traffic generator's specified port
            Args:
             handle ('obj'): Handle of previously created subinterface group
            Returns:
             None
        '''
        raise NotImplementedError