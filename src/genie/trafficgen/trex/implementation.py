
import time
import logging
import ipaddress
from prettytable import PrettyTable

# pyATS
from pyats.log.utils import banner

# Genie
from genie.trafficgen.trafficgen import TrafficGen
from genie.harness.exceptions import GenieTgnError

# Logger
log = logging.getLogger(__name__)

# TRex
try:
    from trex_hltapi.hltapi import TRexHLTAPI
    from trex_hltapi import DhcpMessageType
    from trex_hltapi import make_multicast_ipv6
    from trex_hltapi import make_multicast_mac
    from trex_hltapi import ALL_IPV6_NODES_MULTICAST
    from trex_hltapi.utils.tools import mac_to_colon_notation
    from trex_hltapi import (make_link_local_ipv6, make_multicast_mac, DhcpMessageType, Dhcpv6MessageType,
    Dhcpv6OptCode, ALL_IPV6_NODES_MULTICAST, ALL_DHCPV6_SERVERS_MULTICAST)
except:
    log.warning('trex_hltapi must be installed to use the trex traffic gen')

class Trex(TrafficGen):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._is_connected = False
        self._traffic_profile_configured = False
        self._latest_stats = {}
        self._latest_stats_stream = {}
        self._traffic_statistics_table = PrettyTable()
        self._traffic_statistics_table_stream = PrettyTable()
        self._traffic_streams = []
        self.pktcnt_hdl = {}

        # Internal variables
        self.igmp_clients = {}
        self.mld_clients = {}

        # Get TRex device from testbed
        try:
            self._trex = TRexHLTAPI()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("TRex API returned error") from e

        log.info(self.connection_info)

        for key in ['username', 'reset', 'break_locks', 'raise_errors', \
            'verbose', 'timeout', 'device_ip', 'port_list', 'ip_src_addr', \
            'ip_dst_addr', 'intf_ip_list', 'gw_ip_list']:
            try:
                setattr(self, key, self.connection_info[key])
            except Exception:
                raise GenieTgnError("Argument '{k}' not found in testbed"
                                    "for device '{d}'"
                                    .format(k=key, d=self.device.name))

    def configure_interface(self, arp_send_req=False, arp_req_retries=3,
                            multicast=False, vlan=False):
        ''' Method to configure the interfaces on the TRex device.
            This needs to be configured before starting traffic. '''

        try:
            self._trex.interface_config(
                    port_handle=self.port_list,
                    arp_send_req=arp_send_req,
                    arp_req_retries=arp_req_retries,
                    intf_ip_addr=self.intf_ip_list,
                    gateway=self.gw_ip_list,
                    multicast=multicast,
                    vlan=vlan)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure interfaces on TRex device") from e

    def isconnected(self):
        ''' Method to check connectivity to TRex device '''
        return self._trex is not None and self._trex.is_connected()

    def connect(self, configure_interface_flag=True):
        '''Connect to TRex'''

        log.info(banner("Connecting to TRex"))

        # try connecting
        try:
            self._trex.connect(device = self.device_ip,
                               username = self.username,
                               reset = self.reset,
                               break_locks = self.break_locks,
                               raise_errors = self.raise_errors,
                               verbose = self.verbose,
                               timeout = self.timeout,
                               port_list = self.port_list)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to connect to TRex device") from e
        else:
            self._is_connected = self.isconnected()
            log.info("Connected to TRex successfully")

        # configure the interfaces on the TREX, the interfaces have to
        # configured before starting the traffic
        if configure_interface_flag:
            self.configure_interface()

    def disconnect(self):
        ''' Disconnect from TRex, this will call _trex.traffic_config
        with mode = 'remove' and will also remove traffic, reset source
        and destination ip addresses, promiscuous modes and so on, and
        disconnects from TRex '''

        self._trex.cleanup_session(port_handle = 'all')
        self._is_connected = self.isconnected()

    def send_rawip(self, interface, mac_src, mac_dst, ip_src, ip_dst,
                   vlanid=0, count=1, pps=100):
        '''Send rawip packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, exaple aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlanid ('int', optional): vlan id, default is 0
             count ('int', optional): send packets count, default is 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
        '''
        mac_src = mac_to_colon_notation(mac_src)
        mac_dst = mac_to_colon_notation(mac_dst)
        trex_ns = self._trex.get_trex_namespace().ns

        with trex_ns.trex_client_context():
            from scapy.all import IP, Ether, Dot1Q
            ether_part = Ether(src=mac_src, dst=mac_dst)
            ip_part = IP(src=ip_src, dst=ip_dst)
            if vlanid:
                scapy_pkt = ether_part / Dot1Q(vlan=vlanid) / ip_part
            else:
                scapy_pkt = ether_part / ip_part
            pkt = trex_ns.trex.stl.api.STLPktBuilder(pkt=scapy_pkt)
            bst_mode = trex_ns.trex.stl.api.STLTXSingleBurst(
                pps=pps, total_pkts=count
            )
            flow = trex_ns.trex.stl.api.STLStream(packet=pkt,
                                                  mode=bst_mode)
            self._trex.get_stl_client().client.remove_all_streams(
                ports=interface
            )
            self._trex.get_stl_client().client.add_streams(ports=interface,
                                                           streams=flow)
            self._trex.get_stl_client().client.start(ports=interface)
            self._trex.get_stl_client().client.wait_on_traffic(
                ports=interface
            )
            time.sleep(5)

    def start_pkt_count_rawip(self, interface, mac_src, mac_dst,
                              ip_src, ip_dst, vlan_tag=0):
        '''Start ip packet count
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
        '''
        ports = interface if isinstance(interface, list) else [interface]

        self._trex.get_stl_client().client.set_port_attr(ports=ports,
                                                         promiscuous=True)
        self._trex.get_stl_client().client.set_service_mode(ports=ports)
        pfilter = "ether dst {} and ether src {} and vlan {} "\
                    "and dst host {} and src host {}".format(mac_dst, mac_src,
                                                            vlan_tag,
                                                            ip_dst, ip_src)

        for port in ports:
            result = self._trex.get_stl_client().client.start_capture(
                rx_ports=[port],
                limit=1,
                bpf_filter=pfilter,
            )
            self.pktcnt_hdl[port] = {'cap_id': result['id']}

    def send_rawipv6(self, interface, mac_src, mac_dst, ipv6_src, ipv6_dst,
                     vlanid=0, count=1, pps=100):
        '''Send rawipv6 packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, exaple aabb.bbcc.ccdd
             ipv6_src ('str'): source ipv6 address
             ipv6_dst ('str'): destination ipv6 address
             vlanid ('int', optional): vlan id, default = 0
             count ('int', optional): send packets count, default = 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
        '''
        mac_src = mac_to_colon_notation(mac_src)
        mac_dst = mac_to_colon_notation(mac_dst)
        trex_ns = self._trex.get_trex_namespace().ns

        with trex_ns.trex_client_context():
            from scapy.all import IPv6, Ether, Dot1Q
            ether_part = Ether(src=mac_src, dst=mac_dst)
            ip_part = IPv6(src=ipv6_src, dst=ipv6_dst, hlim=1)
            if vlanid:
                scapy_pkt = ether_part / Dot1Q(vlan=vlanid) / ip_part
            else:
                scapy_pkt = ether_part / ip_part
            pkt = trex_ns.trex.stl.api.STLPktBuilder(pkt=scapy_pkt)
            bst_mode = trex_ns.trex.stl.api.STLTXSingleBurst(
                pps=pps, total_pkts=count
            )
            flow = trex_ns.trex.stl.api.STLStream(packet=pkt,
                                                        mode=bst_mode)
            self._trex.get_stl_client().client.remove_all_streams(
                ports=interface
            )
            self._trex.get_stl_client().client.add_streams(ports=interface,
                                                        streams=flow)
            self._trex.get_stl_client().client.start(ports=interface)
            self._trex.get_stl_client().client.wait_on_traffic(
                ports=interface
            )

    def start_pkt_count_rawipv6(self, interface, mac_src, mac_dst,
                                ipv6_src, ipv6_dst, vlan_tag=0):
        '''Start ipv6 packet count
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
        '''
        ports = interface if isinstance(interface, list) else [interface]

        self._trex.get_stl_client().client.set_port_attr(ports=ports,
                                                         promiscuous=True)
        self._trex.get_stl_client().client.set_service_mode(ports=ports)
        pfilter = "ether dst {} and ether src {} and vlan {} "\
                    "and dst host {} and src host {}".format(mac_dst, mac_src,
                                                            vlan_tag,
                                                            ipv6_dst, ipv6_src)

        for port in ports:
            result = self._trex.get_stl_client().client.start_capture(
                rx_ports=[port],
                limit=1,
                bpf_filter=pfilter,
            )

            self.pktcnt_hdl[port] = {'cap_id': result['id']}

    def stop_pkt_count(self, interface):
        '''Stop ip packet count
           Args:
             interface ('str' or 'list'): interface name
                                  or list of interface names
                                  shall be same as passed in start_pkt_count
           Returns:
             None
        '''
        ports = interface if isinstance(interface, list) else [interface]

        for intf in ports:
            self._trex.get_stl_client().client.stop_capture(
                capture_id=self.pktcnt_hdl[intf]['cap_id']
            )
            self._trex.get_stl_client().client.set_service_mode(ports=intf,
                                                                enabled=False)

    def get_pkt_count(self, interface):
        '''Get ip packet count and stop pkt capture
           Args:
             interface ('str'): interface name
           Returns:
             count('int')
        '''
        stats = self._trex.get_stl_client().client.get_capture_status()
        caps = stats[self.pktcnt_hdl[interface]['cap_id']]
        packet_stats = caps['matched']
        return packet_stats

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
        '''
        map_addr = int(ipaddress.ip_address(ip_dst))
        map_addr = map_addr & 0x7FFFFF
        mac_dst = '0100.5E%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        self.start_pkt_count_rawip(interface, mac_src, mac_dst,
                                   ip_src, ip_dst, vlan)

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
        '''
        map_addr = int(ipaddress.ip_address(ip_dst))
        map_addr = map_addr & 0x7FFFFF
        mac_dst = '0100.5E%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        self.send_rawip(interface, mac_src, mac_dst, ip_src, ip_dst,
                        vlan, count, pps)

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
             None
        '''
        mac_src = mac_to_colon_notation(mac_src)

        trex_ns = self._trex.get_trex_namespace().ns
        with trex_ns.trex_client_context():
            from scapy.all import IP, Ether, Dot1Q, ARP
            ether_part = Ether(src=mac_src, dst='ff:ff:ff:ff:ff:ff')
            #Op=1 indicates ARP request and OP=2 indicates ARP reply
            if ip_src == ip_target:
                arp_part = ARP(op=2, hwsrc=mac_src, psrc=ip_src,
                                hwdst='ff:ff:ff:ff:ff:ff',
                                pdst=ip_target)
            else:
                arp_part = ARP(op=1, hwsrc=mac_src, psrc=ip_src,
                                hwdst='00:00:00:00:00:00',
                                pdst=ip_target)
            if vlan_tag:
                scapy_pkt = ether_part / Dot1Q(vlan=vlan_tag) / arp_part
            else:
                scapy_pkt = ether_part / arp_part

            pkt = trex_ns.trex.stl.api.STLPktBuilder(pkt=scapy_pkt)
            bst_mode = trex_ns.trex.stl.api.STLTXSingleBurst(
                pps=pps, total_pkts=count
            )
            flow = trex_ns.trex.stl.api.STLStream(packet=pkt,
                                                  mode=bst_mode)
            self._trex.get_stl_client().client.remove_all_streams(
                ports=interface
            )
            self._trex.get_stl_client().client.add_streams(ports=interface,
                                                           streams=flow)
            self._trex.get_stl_client().client.start(ports=interface)
            self._trex.get_stl_client().client.wait_on_traffic(
                ports=interface
            )

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
             None
        '''
        mac_src = mac_to_colon_notation(mac_src)
        trex_ns = self._trex.get_trex_namespace().ns
        with trex_ns.trex_client_context():
            from scapy.all import Ether, Dot1Q
            from scapy.all import IPv6, ICMPv6ND_NS
            from scapy.all import ICMPv6NDOptSrcLLAddr

            ether_p = Ether(src=mac_src, dst=make_multicast_mac(ip_dst))

            ipv6_p = IPv6(src=ip_src, dst=make_multicast_ipv6(ip_dst))
            icmpv6_p = ICMPv6ND_NS(tgt=ip_dst)
            icmpv6_opt = ICMPv6NDOptSrcLLAddr(lladdr=mac_src)
            if vlan_tag:
                scapy_pkt = \
                  ether_p / Dot1Q(vlan=vlan_tag) / ipv6_p / icmpv6_p / icmpv6_opt
            else:
                scapy_pkt = ether_p / ipv6_p / icmpv6_p / icmpv6_opt

            pkt = trex_ns.trex.stl.api.STLPktBuilder(pkt=scapy_pkt)
            bst_mode = trex_ns.trex.stl.api.STLTXSingleBurst(
                pps=pps, total_pkts=count
            )
            flow = trex_ns.trex.stl.api.STLStream(packet=pkt,
                                                  mode=bst_mode)
            self._trex.get_stl_client().client.remove_all_streams(
                ports=interface
            )
            self._trex.get_stl_client().client.add_streams(ports=interface,
                                                           streams=flow)
            self._trex.get_stl_client().client.start(ports=interface)
            self._trex.get_stl_client().client.wait_on_traffic(
                ports=interface
            )

    def send_ndp_na(self, interface, mac_src, mac_dst, ip_src, ip_dst,
                    vlan_tag=0, count=1, pps=100):
        '''Send ndp neighbor solicitation packet
           Args:
             interface ('str'): interface name
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             mac_dst ('str'): destination mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan_tag ('int', optional): vlan tag, default 0
             count ('int', optional): send packets count, default 1
             pps ('int', optional): packets per second, default 100
           Returns:
             None
           Raises:
             None
        '''
        mac_src = mac_to_colon_notation(mac_src)

        solicited = 1
        if 'FF02::1' == ip_dst or 'ff02::1' == ip_dst:
            mac_dst = make_multicast_mac(ip_dst)
            solicited = 0

        mac_dst = mac_to_colon_notation(mac_dst)

        trex_ns = self._trex.get_trex_namespace().ns
        with trex_ns.trex_client_context():
            from scapy.all import Ether, Dot1Q
            from scapy.all import IPv6, ICMPv6ND_NA
            from scapy.all import ICMPv6NDOptSrcLLAddr

            ether_p = Ether(src=mac_src, dst=mac_dst)

            ipv6_p = IPv6(src=ip_src, dst=ip_dst)
            icmpv6_p = ICMPv6ND_NA(R=0, S=solicited, O=1, tgt=ip_src)
            icmpv6_opt = ICMPv6NDOptSrcLLAddr(type=2, lladdr=mac_src)
            if vlan_tag:
                scapy_pkt = \
                  ether_p / Dot1Q(vlan=vlan_tag) / ipv6_p / icmpv6_p / icmpv6_opt
            else:
                scapy_pkt = ether_p / ipv6_p / icmpv6_p / icmpv6_opt

            pkt = trex_ns.trex.stl.api.STLPktBuilder(pkt=scapy_pkt)
            bst_mode = trex_ns.trex.stl.api.STLTXSingleBurst(
                pps=pps, total_pkts=count
            )
            flow = trex_ns.trex.stl.api.STLStream(packet=pkt,
                                                  mode=bst_mode)
            self._trex.get_stl_client().client.remove_all_streams(
                ports=interface
            )
            self._trex.get_stl_client().client.add_streams(ports=interface,
                                                           streams=flow)
            self._trex.get_stl_client().client.start(ports=interface)
            self._trex.get_stl_client().client.wait_on_traffic(
                ports=interface
            )

    def configure_traffic_profile(self, bidirectional=False, frame_size=60, ignore_macs=True,
            l3_protocol='ipv4', ip_src_mode='increment', ip_src_count=254,
            ip_dst_mode='increment', ip_dst_count=254, l4_protocol='udp',
            udp_dst_port=1209, udp_src_port=1025, rate_pps=1000, count=3):
        ''' Configure the traffic profile, the profile has to be configured
            before calling the start_traffic method.
        '''

        # This is just to get individual stream id for each dst IP/port pair
        # otherwise it just returns one stream-id
        ip_src_string = self.ip_src_addr
        ip_dst_string = self.ip_dst_addr
        for _ in range(count):
            try:
                config_status = self._trex.traffic_config(
                mode = 'create',
                bidirectional = bidirectional,
                port_handle = self.port_list[1],
                port_handle2 = self.port_list[0],
                frame_size = frame_size,
                ignore_macs = ignore_macs,
                l3_protocol = l3_protocol,
                ip_src_addr = ip_src_string,
                ip_src_mode = ip_src_mode,
                ip_src_count = ip_src_count,
                ip_dst_addr = ip_dst_string,
                ip_dst_mode = ip_dst_mode,
                ip_dst_count = ip_dst_count,

                l4_protocol = l4_protocol,
                udp_dst_port = udp_dst_port,
                udp_src_port = udp_src_port,

                rate_pps = rate_pps
            )
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Failed to configure traffice profile on TRex")
            else:
                self._traffic_streams.append(config_status['stream_id'])
                stream_list = str(self._traffic_streams)[1:-1]
                log.info("Traffic config streams: " + stream_list)

            log.info("Src IP: " + ip_src_string)
            log.info("Dst IP: " + ip_dst_string)
            ip_src_string = str(ipaddress.IPv4Address(ip_src_string) + 1)
            ip_dst_string = str(ipaddress.IPv4Address(ip_dst_string) + 1)

        self._traffic_profile_configured = True

    def configure_dhcpv4_request(self, interface, mac_src, requested_ip, xid=0,
                                 transmit_mode='single_burst', pkts_per_burst=1, pps=100):
        ''' Method to configure a DHCPv4 REQUEST stream '''

        try:
            config_status = self._trex.traffic_config (
                mode='create',
                port_handle=interface,
                length_mode='auto',
                mac_src=mac_src,
                mac_dst='ff:ff:ff:ff:ff:ff',
                l3_protocol='ipv4',
                ip_src_addr='0.0.0.0',
                ip_dst_addr='255.255.255.255',

                l4_protocol='dhcp',
                dhcp_transaction_id=xid,
                dhcp_client_hw_addr=mac_src,
                dhcp_client_ip_addr=requested_ip,
                dhcp_option=['dhcp_message_type'],
                dhcp_option_data=[DhcpMessageType.REQUEST],
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure dhcpv4 request stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_dhcpv4_reply(self, interface, mac_src, ip_src, assigned_ip,
                               lease_time, xid=0, transmit_mode='single_burst',
                               pkts_per_burst=1, pps=100):
        ''' Method to configure a DHCPv4 REPLY stream '''

        try:
            config_status = self._trex.traffic_config(
                mode='create',
                port_handle=interface,
                length_mode='auto',
                mac_src=mac_src,
                mac_dst="ff:ff:ff:ff:ff:ff",
                l3_protocol='ipv4',
                ip_src_addr=ip_src,
                ip_dst_addr='255.255.255.255',

                l4_protocol='dhcp',
                dhcp_transaction_id=xid,
                dhcp_operation_code='reply',
                dhcp_client_hw_addr=mac_src,
                dhcp_your_ip_addr=assigned_ip,
                dhcp_option=['dhcp_message_type', 'dhcp_ip_addr_lease_time'],
                dhcp_option_data=[DhcpMessageType.ACK, lease_time],
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure dhcpv4 reply stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_dhcpv6_request(self, interface, src_mac, requested_ip,
                            cid=None, sid=None,
                            vlan_id=0, xid=0,
                            transmit_mode='single_burst',
                            pkts_per_burst=1, pps=100):
        ''' Method to configure a DHCPv6 REQUEST stream '''

        try:
            config_status = self._trex.traffic_config(
                mode='create',
                port_handle=interface,

                length_mode='auto',
                l3_protocol='ipv6',
                mac_src=src_mac,
                mac_dst=make_multicast_mac(ALL_DHCPV6_SERVERS_MULTICAST),
                ipv6_src_addr=make_link_local_ipv6(src_mac),
                ipv6_dst_addr=ALL_DHCPV6_SERVERS_MULTICAST,

                l4_protocol='dhcp',
                dhcp6_opt_ia_address=requested_ip,
                dhcp6_message_type=Dhcpv6MessageType.REQUEST,
                dhcp6_transaction_id=xid,
                dhcp6_opt_server_id_duid=sid,
                dhcp6_opt_client_id_duid=cid,
                dhcp6_opt_req_opts=[
                    Dhcpv6OptCode.DNS_SERRVERS,
                    Dhcpv6OptCode.DNS_DOMAINS,
                    Dhcpv6OptCode.CLIENT_FQDN
                ],

                vlan_id=vlan_id,
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure dhcpv6 request stream on TRex")

        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_arp_request(self, port, mac_src, ip_src, ip_dst, frame_size=60,
                              vlan_id=0, transmit_mode='single_burst',
                              pkts_per_burst=1, pps=100):
        ''' Method to configure an ARP request stream '''

        try:
            config_status = self._trex.traffic_config(
                # Configure stream
                mode='create',
                port_handle=port,

                # Configure layer 2 settings
                frame_size=frame_size,
                mac_src=mac_src,
                mac_dst='ff:ff:ff:ff:ff:ff',
                vlan_id=vlan_id,

                # Configure layer 3 settings
                l3_protocol='arp',
                arp_src_hw_addr=mac_src,
                arp_dst_hw_addr='ff:ff:ff:ff:ff:ff',
                arp_psrc_addr=ip_src,
                arp_pdst_addr=ip_dst,
                arp_operation='arpRequest',

                # Configure transmit settings
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure ARP request stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_garp(self, port, mac_src, ip, frame_size=60,
                       vlan_id=0, transmit_mode='single_burst',
                       pkts_per_burst=1, pps=100):
        ''' Method to configure a GARP stream '''

        try:
            config_status = self._trex.traffic_config(
                # Configure stream
                mode='create',
                port_handle=port,

                # Configure layer 2 settings
                frame_size=frame_size,
                mac_src=mac_src,
                mac_dst='ff:ff:ff:ff:ff:ff',
                vlan_id=vlan_id,

                # Configure layer 3 settings
                l3_protocol='arp',
                arp_src_hw_addr=mac_src,
                arp_dst_hw_addr='ff:ff:ff:ff:ff:ff',
                arp_psrc_addr=ip,
                arp_pdst_addr=ip,
                arp_operation='arpReply',

                # Configure transmit settings
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure GARP stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_dhcpv6_reply(self, interface, src_mac, src_ip, assigned_ip, lease_time,
                          cid=None, sid=None, vlan_id=0, xid=0,
                          transmit_mode='single_burst',
                          pkts_per_burst=1, pps=100):
        ''' Method to configure a DHCPv6 REPLY stream '''
        try:
            config_status = self._trex.traffic_config(
                mode='create',
                port_handle=interface,
                length_mode='auto',

                l3_protocol='ipv6',
                mac_src=src_mac,
                mac_dst=make_multicast_mac(ALL_IPV6_NODES_MULTICAST),
                ipv6_src_addr = src_ip,
                ipv6_dst_addr=ALL_IPV6_NODES_MULTICAST,

                l4_protocol='dhcp',
                dhcp6_message_type=Dhcpv6MessageType.REPLY,
                dhcp6_transaction_id=xid,

                dhcp6_opt_client_id_duid=cid,
                dhcp6_opt_server_id_duid=sid,
                dhcp6_opt_ia_id=xid,
                dhcp6_opt_ia_address=assigned_ip,
                dhcp6_opt_ia_address_valid_lifetime=lease_time,

                vlan_id=vlan_id,
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
                )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure dhcpv6 reply stream on TRex")

        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_ipv4_data_traffic(self, interface, src_ip, dst_ip,
                                    l4_protocol, payload, transmit_mode='single_burst',
                                    pkts_per_burst=1, pps=100):
        '''Method to configure ipv4 data traffic stream'''
        try:
            config_status = self._trex.traffic_config(
                mode='create',
                port_handle=interface,
                length_mode='auto',
                ignore_macs=True,
                ip_src_addr=src_ip,
                ip_dst_addr=dst_ip,

                l3_protocol='ipv4',
                l4_protocol=l4_protocol,
                payload=bytes(str.encode(payload)),
                rate_pps=pps,
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure ipv4 data packet stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_ipv6_data_traffic(self, interface, src_ip, dst_ip,
                                    l4_protocol, payload, transmit_mode='single_burst',
                                    pkts_per_burst=1, pps=100):
        '''Method to configure ipv6 data traffic stream'''

        try:
            config_status = self._trex.traffic_config(
                mode='create',
                port_handle=interface,
                length_mode='auto',
                ignore_macs=True,
                ipv6_src_addr=src_ip,
                ipv6_dst_addr=dst_ip,

                l3_protocol='ipv6',
                l4_protocol=l4_protocol,
                payload=bytes(str.encode(payload)),
                rate_pps=pps,
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure ipv6 data packet stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_acd(self, port, mac_src, ip_dst, frame_size=60,
                      vlan_id=0, transmit_mode='single_burst',
                      pkts_per_burst=1, pps=100):
        ''' Method to configure an address conflict detection stream '''

        try:
            config_status = self._trex.traffic_config(
                # Configure stream
                mode='create',
                port_handle=port,

                # Configure layer 2 settings
                frame_size=frame_size,
                mac_src=mac_src,
                mac_dst='00:00:00:00:00:00',
                vlan_id=vlan_id,

                # Configure layer 3 settings
                l3_protocol='arp',
                arp_src_hw_addr=mac_src,
                arp_dst_hw_addr='00:00:00:00:00:00',
                arp_psrc_addr='0.0.0.0',
                arp_pdst_addr=ip_dst,
                arp_operation='arpRequest',

                # Configure transmit settings
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure ACD stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_ns(self, interface, mac_src, ip_src, ip_dst, hop_limit=255,
                     length_mode='auto', vlan_id=0, transmit_mode='single_burst',
                     pkts_per_burst=1, pps=100):
        ''' Method to configure an NS stream '''

        try:
            config_status = self._trex.traffic_config(
                # Configure stream
                mode='create',
                port_handle=interface,

                # Configure layer 2 settings
                ipv6_hop_limit=hop_limit,
                mac_src=mac_src,
                mac_dst=make_multicast_mac(ip_src),
                length_mode=length_mode,

                # Configure layer 3 settings
                l3_protocol='ipv6',
                ipv6_src_addr=ip_src,
                ipv6_dst_addr=make_multicast_ipv6(ip_dst),
                vlan_id=vlan_id,

                # Configure layer 4 settings
                l4_protocol='icmp',
                icmp_type='nd_ns',
                icmp_nd_target=ip_dst,
                icmp_nd_opt_src_lladr=mac_src,

                # Configure transmit settings
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure NS stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_na(self, interface, mac_src, ip_src, ip_dst, solicited=True,
                     hop_limit=255, length_mode='auto', vlan_id=0,
                     transmit_mode='single_burst', pkts_per_burst=1, pps=100):
        ''' Method to configure an NA stream '''

        if solicited:
            mac_dst = make_multicast_mac(ip_dst)
            ip_multicast_dst = make_multicast_ipv6(ip_dst)
        else:
            mac_dst = make_multicast_mac(ALL_IPV6_NODES_MULTICAST)
            ip_multicast_dst = ALL_IPV6_NODES_MULTICAST

        try:
            config_status = self._trex.traffic_config(
                # Configure stream
                mode='create',
                port_handle=interface,

                # Configure layer 2 settings
                ipv6_hop_limit=hop_limit,
                mac_src=mac_src,
                mac_dst=mac_dst,
                length_mode=length_mode,
                vlan_id=vlan_id,

                # Configure layer 3 settings
                l3_protocol='ipv6',
                ipv6_src_addr=ip_src,
                ipv6_dst_addr=ip_multicast_dst,

                # Configure layer 4 settings
                l4_protocol='icmp',
                icmp_type='nd_na',
                icmp_nd_target=ip_src,
                icmp_nd_opt_src_lladr=mac_src,

                # Configure transmit settings
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure NA stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_dad(self, interface, mac_src, ip_dst, hop_limit=255,
                      length_mode='auto', vlan_id=0, transmit_mode='single_burst',
                      pkts_per_burst=1, pps=100):
        ''' Method to configure a DAD stream '''

        try:
            config_status = self._trex.traffic_config(
                # Configure stream
                mode='create',
                port_handle=interface,

                # Configure layer 2 settings
                ipv6_hop_limit=hop_limit,
                mac_src=mac_src,
                mac_dst=make_multicast_mac(ip_dst),
                length_mode=length_mode,
                vlan_id=vlan_id,

                # Configure layer 3 settings
                l3_protocol='ipv6',
                ipv6_src_addr='::',
                ipv6_dst_addr=make_multicast_ipv6(ip_dst),

                # Configure layer 4 settings
                l4_protocol='icmp',
                icmp_type='nd_ns',
                icmp_nd_target=ip_dst,

                # Configure transmit settings
                transmit_mode=transmit_mode,
                pkts_per_burst=pkts_per_burst,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure DAD stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def get_traffic_stream_names(self):
        '''Returns a list of all traffic stream names present in current
        configuration'''

        return self._traffic_streams

    def start_traffic(self, port=None, wait_time=10):
        '''Start traffic for specified port(s) on TRex'''

        if port is None:
            port = self.port_list

        # Check if traffic profile is configured
        if not self._traffic_profile_configured:
            raise GenieTgnError("No traffic profile configured on device'{}'".\
                                format(self.device.name))

        log.info(banner("Starting traffic for specified port(s) on TRex"))

        # Start traffic
        try:
            start_traffic = self._trex.traffic_control(action = 'run', port_handle = port)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)

    def start_traffic_streams(self, wait_time=5, streams = None):
        '''Start traffic on TRex'''

        if not streams:
            streams = self._traffic_streams
        # Configure traffic profile first
        if not self._traffic_profile_configured:
            self.configure_traffic_profile()

        log.info(banner("Starting port trasmit first on TRex"))
        ## Start traffic
        try:
            start_traffic = self._trex.traffic_control(action = 'run', port_handle = self.port_list[1])
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds after configuring ports".format(d = wait_time))
        time.sleep(wait_time)
        # Start traffic per stream
        try:
            start_traffic = self._trex.traffic_control(action = 'run', handle = streams)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic per stream on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds after starting traffic".format(d = wait_time))
        time.sleep(wait_time)

    def unconfigure_traffic(self):
        '''Unconfigure traffic. This will remove the profile configured.
           There is an option to unconfigure per port as well.
        '''

        log.info(banner("Unconfiguring TRex traffic profile"))
        try:
            self._trex.traffic_config(mode = 'remove', port_handle = self.port_list, stream_id = 'all')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to unconfigure traffic profile on TRex")
        log.info(banner("Unconfigured TRex traffic profile"))

        self._traffic_profile_configured = False

    def stop_traffic(self, port=None, wait_time=10, unconfig_traffic=True, print_stats=False):
        '''Stop traffic for specified port(s) on TRex'''

        log.info(banner("Stopping traffic for specified port(s) on TRex"))

        if port is None:
            port = self.port_list

        # Stop traffic
        try:
            stop_traffic = self._trex.traffic_control(action = 'stop', port_handle = port)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)

        if print_stats:
            self.print_statistics(mode='aggregate')

        # Get the _traffic_statistics_table before unconfiguring
        self._traffic_statistics_table = self.create_traffic_statistics_table()
        log.info(self._traffic_statistics_table)
        # if needed to unconfigure traffic after stopping
        if unconfig_traffic:
            self.unconfigure_traffic()

    def stop_traffic_streams(self, wait_time=5, unconfig_traffic=False, streams = None, print_stats = False):
        '''Stop traffic on given streams on TRex'''

        log.info(banner("Stopping traffic for given streams on TRex"))
        if streams is None:
            streams = self._traffic_streams
        # Stop traffic
        try:
            stop_traffic = self._trex.traffic_control(action = 'stop', handle = streams)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)

        if print_stats:
            self.print_statistics(mode='streams')

        # Get the _traffic_statistics_table before unconfiguring
        self._traffic_statistics_table_stream = self.create_traffic_statistics_table_stream(traffic_streams = streams)

        log.info(self._traffic_statistics_table)
        # if needed to unconfigure traffic after stopping
        if unconfig_traffic:
            self.unconfigure_traffic()

    def print_statistics(self, mode = 'aggregate'):
        '''Print traffic related statistics'''
        res = self._trex.traffic_stats(mode = mode, port_handle = self.port_list)
        log.info(res)

    def clear_statistics(self, port_handle_clear=None, wait_time=5, clear_port_stats=True,
                         clear_protocol_stats=True):
        '''Clear all traffic, port, protocol statistics on TRex'''

        log.info(banner("Clearing traffic statistics"))
        # Clear trafficstats, TRex api does not support per port/protocol clear
        if not port_handle_clear:
            log.info("Clearing statistics for all ports since port handle is empty")
            port_handle_clear = self.port_list

        if not clear_port_stats:
            return

        try:
            clear_traffic_stats = self._trex.traffic_control(action="clear_stats", port_handle=port_handle_clear)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to clear traffic stats on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Successfully cleared traffic statistics on device\
                     '{dev}'".format(dev=self.device.name))

        # Wait after clearing statistics
        log.info("Waiting for '{}' seconds after clearing statistics".\
                    format(wait_time))
        time.sleep(wait_time)

    def create_traffic_statistics_table(self, set_golden=False, clear_stats=False, clear_stats_time=30, view_create_interval=30, view_create_iteration=5):
        '''Returns traffic profile of configured streams on TRex'''

        # Initialize the table
        traffic_table = PrettyTable()
        traffic_table.field_names = ['Port', 'Tx/Rx', 'Packet Bit Rate',
                                     'Packet Byte Count',
                                     'Packet Count', 'Packet Rate',
                                     'Total_pkt_bytes', 'Total Packet Rate',
                                     'Total Packets']

        stat = self._trex.traffic_stats(mode = 'aggregate',
                                        port_handle = self.port_list)
        self._latest_stats = stat
        for port in stat:
            data = [port, 'Tx']
            for key in stat[port]['aggregate']['tx']:
                data.append(stat[port]['aggregate']['tx'][key])
            traffic_table.add_row(data)
            # remove the values from Tx from 1:end, since these have been added
            # to the table now
            del data[1:]
            data.append('Rx')
            for key in stat[port]['aggregate']['rx']:
                data.append(stat[port]['aggregate']['rx'][key])
            traffic_table.add_row(data)

        return traffic_table

    def create_traffic_statistics_table_stream(self, set_golden=False,
            clear_stats=False, clear_stats_time=30, view_create_interval=30,
            view_create_iteration=5, traffic_streams=None):
        '''Returns traffic profile of configured streams on TRex'''

        if not traffic_streams:
            log.info("Need to specify the stream_id to create the stats table")
            traffic_streams = self._traffic_streams

        for stream in traffic_streams:
            if stream not in self._traffic_streams:
                log.info("Stream: '{s}' not configured".format(s=stream))

        # Initialize the table
        traffic_table = PrettyTable()
        traffic_table.field_names = ['Port', 'Stream', 'Tx/Rx', 'Total pkts', 'Total_pkt_bytes', 'Total_pkt_bit_rate', 'Total_pkt_rate', 'line rate percent']

        # TODO: no hltapi to check if stat is empty?
        # stat is 'trex_hltapi.utils.wrappers.HltApiResult'
        stat = self._trex.traffic_stats(mode = 'streams',
                                        port_handle = self.port_list)

        self._latest_stats_stream  = stat
        for port in stat:
            num_streams = len(stat[port]['stream'])
            for stream_id in stat[port]['stream'].keys():
                data = [port, str(stream_id), 'tx']
                for key in stat[port]['stream'][str(stream_id)]['tx'].keys():
                    data.append(stat[port]['stream'][str(stream_id)]['tx'][key])
                traffic_table.add_row(data)
                # remove the values from Tx from 2:end, since these have been added
                # to the table now
                del data[2:]
                data.append('rx')
                for key in stat[port]['stream'][str(stream_id)]['rx'].keys():
                    data.append(stat[port]['stream'][str(stream_id)]['rx'][key])
                traffic_table.add_row(data)

        return traffic_table

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
        '''
        grp_hdl = self._trex.emulation_multicast_group_config(mode='create',
                                                             ip_addr_start=groupip,
                                                             ip_prefix_len=ip_prefix_len,
                                                             ip_addr_step=inc_steps,
                                                             num_groups=group_nums)
        return grp_hdl

    def delete_multicast_group(self, group_handler):
        '''delete multicast group pool
           Args:
             group_handler ('obj'): multicast group pool handler
           Returns:
             True
        '''
        self._trex.emulation_multicast_group_config(mode='delete',
                                                    handle=group_handler.handle)
        return True

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
             KeyError
        '''
        multicast_handle = self._trex.emulation_multicast_source_config(mode='create',
                                                                        ip_addr_start=sourceip,
                                                                        ip_addr_step=inc_steps,
                                                                        ip_prefix_len=ip_prefix_len,
                                                                        num_sources=source_nums)
        if not multicast_handle:
            log.warn('multicast source creation failed')
            raise KeyError
        return multicast_handle

    def delete_multicast_source(self, source_handler):
        '''delete multicast source pool
           Args:
             source_handler ('obj'): multicast source pool handler
           Returns:
             True
        '''
        self._trex.emulation_multicast_source_config(mode='delete',
                                                     handle=source_handler.handle)
        return True

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
        '''
        if version == 2:
            version = 'v2'
        else:
            version = 'v3'

        handle = self._get_igmpclient_hkey(interface, vlanid, clientip, version)
        self._update_igmpclient_field(handle.handles[0], 'vlan', vlanid)
        self._update_igmpclient_field(handle.handles[0], 'version', version)

        return handle

    def delete_igmp_client(self, client_handler):
        '''Delete IGMP Client
           Args:
             client_handler ('obj'): IGMP Client handler
           Returns:
             True/False
        '''
        intf = self._get_igmpclient_field(client_handler.handles[0], 'interface')
        self._trex.emulation_igmp_config(mode='delete',
                                         handle=client_handler.handles[0],
                                         intf_ip_addr=intf,
                                         port_handle=intf)
        self._trex.emulation_igmp_control(mode='start',
                                         port_handle=intf)
        return self._del_igmpclient_hkey(client_handler.handles[0])

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
             if the source_handler is None, filter_mode will be set to exclude
           Returns:
             group membership handler
        '''
        if filter_mode == 'N/A':
            filter_mode = None

        if source_handler:
            source_handler = source_handler.handle

        version = self._get_igmpclient_field(client_handler.handles[0], 'version')
        if version == 'v3':
            if source_handler is None:
                filter_mode = 'exclude'
            grp_hdl = self._trex.emulation_igmp_group_config(
                    mode='create',
                    session_handle=client_handler.handles[0],
                    source_pool_handle=source_handler,
                    group_pool_handle=group_handler.handle,
                    g_filter_mode=filter_mode
            )
        else:
            grp_hdl = self._trex.emulation_igmp_group_config(
                    mode='create',
                    session_handle=client_handler.handles[0],
                    group_pool_handle=group_handler.handle,
            )

        self._add_igmpgroup(source_handler, client_handler.handles[0],
                            group_handler.handle, grp_hdl.handle)
        self._update_igmp_filter(client_handler.handles[0],
                                 grp_hdl.handle, filter_mode)

        return grp_hdl

    def igmp_client_modify_group_filter_mode(self, client_handler,
                                             handler, filter_mode=None, action=None):
        '''IGMP Client modify group member filter mode, Only IGMP v3
           client is supported
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
             filter_mode: include | exclude
           Returns:
             Updated Group membership handler
        '''
        self._trex.emulation_igmp_group_config(mode='modify',
                                               handle=handler.handle,
                                               session_handle=client_handler.handles[0],
                                               g_filter_mode='change_to_'+filter_mode)

        self._update_igmp_filter(client_handler.handles[0], handler.handle, filter_mode)
        return handler

    def igmp_client_del_group(self, client_handler, group_handler,
                              mem_handler, source_handler='*'):
        '''IGMP Client delete group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is None, means (*, g)
             mem_handler ('obj'):
                Group membership handler created by igmp_client_add_group
           Returns:
             True
           Raises:
             KeyError
        '''
        grps = self._get_igmpclient_field(client_handler.handles[0], 'grps')
        if group_handler not in grps:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        if source_handler not in grps[group_handler]:
            log.error('Group does not exist')
            raise KeyError

        if mem_handler not in grps[group_handler][source_handler]:
            log.error('Source does not exist')
            raise KeyError

        self._trex.emulation_igmp_group_config(mode='delete',
                                               handle=mem_handler,
                                               session_handle=client_handler.handles[0])

        del grps[group_handler]
        self._update_igmpclient_field(client_handler.handles[0], 'grps', grps)
        return True

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
             True
        '''
        version = self._get_igmpclient_field(client_handler.handles[0], 'version')
        if mode == 'start':
            if version == 'v2':
                self._trex.emulation_igmp_control(mode='join',
                                                  port_handle=interface)
            else:
                self._trex.emulation_igmp_control(mode='start',
                                                  port_handle=interface)
        else:
            grps = self._get_igmpclient_field(client_handler.handles[0], 'grps')

            if version == 'v2':
                del_grps_list =[]
                for grp in grps:
                    self._trex.emulation_igmp_group_config(mode='modify',
                                                           session_handle=client_handler.handles[0],
                                                           handle=grps[grp]['*'],
                                                           g_action='leave')
                    del_grps_list.append(grp)
                # Send the leave message
                self._trex.emulation_igmp_control(port_handle=interface,
                                                  mode='start')
                # Remove the groups membership from the client
                for grp in del_grps_list:
                    self.igmp_client_del_group(client_handler, grp, grps[grp]['*'])
                # Restart the updated client
                self._trex.emulation_igmp_control(port_handle=interface,
                                                  mode='join')
            else:
                for grp in grps:
                    for src in grps[grp]:
                        self._trex.emulation_igmp_group_config(mode='delete',
                                                               handle=grps[grp][src],
                                                               session_handle=client_handler.handles[0])
                        #get filter
                        filt = self.igmp_clients[client_handler.handles[0]]['filters'][grps[grp][src]]
                        if filt == 'include':
                            g_filter = 'block_old_source'
                            grp_hdl = self._trex.emulation_igmp_group_config(mode='create',
                                                                             session_handle=client_handler.handles[0],
                                                                             group_pool_handle=grp,
                                                                             source_pool_handle='{}/0.0.0.0/1'.format(src),
                                                                             g_filter_mode=g_filter)
                            self._add_igmpgroup(src, client_handler.handles[0], grp, grp_hdl.handle)
                            self._update_igmp_filter(client_handler.handles[0], grp_hdl.handle, 'block_old_source')
                        else:
                            g_filter = 'change_to_include'
                            grp_hdl = self._trex.emulation_igmp_group_config(mode='create',
                                                                             session_handle=client_handler.handles[0],
                                                                             group_pool_handle=grp,
                                                                             g_filter_mode=g_filter)
                            self._add_igmpgroup(src, client_handler.handles[0], grp, grp_hdl.handle)
                            self._update_igmp_filter(client_handler.handles[0], grps[grp][src], 'change_to_include')

                self._trex.emulation_igmp_control(port_handle=interface,
                                                  mode='start')
        return True


    # =============================================================
    # IGMP Client management methods
    # Allocate a clientkey to track all the clients
    # This set of methods used to manage the igmp clients of pagent
    # ==============================================================
    def _get_igmpclient_hkey(self, interface, vlanid, clientip, version):
        '''Get host key of igmp client, create a new key for new client
           Args:
             vlanid ('int'): vlan id
             clientip ('str'): client ip address
           Returns:
             handle of igmp client
        '''
        client_hdl = self._trex.emulation_igmp_config(mode='create',
                                                      port_handle=interface,
                                                      intf_ip_addr=clientip,
                                                      version=version,
                                                      vlan_id=vlanid)

        if client_hdl.handles[0] not in self.igmp_clients:
            self.igmp_clients[client_hdl.handles[0]] = {
                'version': version,
                'grps': {},
                'filters': {},
                'interface': interface,
                'ip': clientip,
            }

        return client_hdl

    def _del_igmpclient_hkey(self, handle):
        '''Delete a igmp client host
           Args:
             hkey ('str'): igmp client host key
           Returns:
             True/False
           Raises:
             None
        '''
        if handle in self.igmp_clients:
            del self.igmp_clients[handle]
            return True

        return False

    def _update_igmpclient_field(self, handle, key, value):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
             value ('any'): field value
           Returns:
             None
           Raises:
             None
        '''
        self.igmp_clients[handle][key] = value
        log.info(
            'Client {handle} update: {key}'.format(
                handle=handle, key=key
            )
        )

    def _get_igmpclient_field(self, client_hdl, key):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
           Returns:
             field value
           Raise:
             KeyError
        '''
        val = self.igmp_clients[client_hdl].get(key)
        if val is None:
            log.warn('Key not in dictionary')
            raise KeyError
        return val

    def _update_igmp_filter(self, client, grp_hdl, filter):
        '''Update filter by group member handle
           Args:
             client_handle ('str'): handler for the client
             group member handle ('str'): generated group member handle
             filter_mode('str'): filter mode 'include' 'exclude'
           Return:
             True
           Raise:
             KeyError
        '''
        if client not in self.igmp_clients:
            log.error('Client does not exist')
            raise KeyError
        if grp_hdl not in self.igmp_clients[client]['filters']:
            log.error('Group does not exist')
            raise KeyError
        self.igmp_clients[client]['filters'][grp_hdl] = filter
        return True

    def _add_igmpgroup(self, source_handler, client_handler, group_handler, grp_hdl):
        '''Add igmpclient to group
           Args:
             source_handle ('str'): source ghandle key
             client_handler (dictionary): client handle
             group_handler (dictionary): group handle
             grp_hdl (dictionary): group member handle
           Returns:
             True
           Raise:
             KeyError
        '''
        if client_handler not in self.igmp_clients:
            raise KeyError
        if group_handler not in self.igmp_clients[client_handler]['grps']:
            self.igmp_clients[client_handler]['grps'][group_handler]={}
        if not source_handler:
            self.igmp_clients[client_handler]['grps'][group_handler]['*']=grp_hdl
        else:
            self.igmp_clients[client_handler]['grps'][group_handler][source_handler]=grp_hdl

        '''filter initialization'''
        self.igmp_clients[client_handler]['filters'][grp_hdl] = None
        return True

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
        '''
        if version == 1:
            version = 'v1'
        else:
            version = 'v2'

        handle = self._get_mldclient_hkey(interface, vlanid, clientip, version)
        self._update_mldclient_field(handle.handles[0], 'vlan', vlanid)
        self._update_mldclient_field(handle.handles[0], 'version', version)

        return handle

    def delete_mld_client(self, client_handler):
        '''Delete MLD Client
           Args:
             client_handler ('obj'): MLD Client handler
           Returns:
             True/False
        '''
        #need to be changed
        intf = self._get_mldclient_field(client_handler.handles[0], 'interface')
        self._trex.emulation_mld_config(mode='delete',
                                        handle=client_handler.handles[0],
                                        intf_ip_addr=intf,
                                        port_handle=intf)
        self._trex.emulation_mld_control(mode='start',
                                         port_handle=intf)
        return self._del_mldclient_hkey(client_handler.handles[0])

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
             for v2 (*,g) which is (0.0.0.0, g)-exclude, the source_handler
             should be None, filter_mode will be exclude
           Returns:
             group membership handler
        '''
        if filter_mode == 'N/A':
            filter_mode = None

        if source_handler:
            source_handler = source_handler.handle

        version = self._get_mldclient_field(client_handler.handles[0], 'version')
        if version == 'v2':
            if source_handler is None:
                filter_mode = 'exclude'
            grp_hdl = self._trex.emulation_mld_group_config(mode='create',
                                                            session_handle=client_handler.handles[0],
                                                            source_pool_handle=source_handler,
                                                            group_pool_handle=group_handler.handle,
                                                            g_filter_mode=filter_mode)
        else:
            grp_hdl = self._trex.emulation_mld_group_config(mode='create',
                                                            session_handle=client_handler.handles[0],
                                                            group_pool_handle=group_handler.handle)

        self._add_mldgroup(source_handler, client_handler.handles[0], group_handler.handle, grp_hdl.handle)
        self._update_mld_filter(client_handler.handles[0], grp_hdl.handle, filter_mode)

        return grp_hdl

    def mld_client_modify_group_filter_mode(self, client_handler,
                                            handler, filter_mode=None):
        '''MLD Client modify group member filter mode, Only MLD v2
           client is supported
           Args:
             client_handler ('obj'): MLD Client handler
             handler ('obj'):
                Group membership handler created by mld_client_add_group
             filter_mode: include | exclude
           Returns:
             Updated Group membership handler
        '''
        self._trex.emulation_mld_group_config(mode='modify',
                                              handle=handler.handle,
                                              session_handle=client_handler.handles[0],
                                              g_filter_mode='change_to_'+filter_mode)

        self._update_mld_filter(client_handler.handles[0], handler.handle, filter_mode)
        return handler

    def mld_client_del_group(self, client_handler, group_handler,
                             mem_handler, source_handler='*'):
        '''MLD Client delete group membership
           Args:
             client_handler ('obj'): MLD Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is None, means (*, g)
             mem_handler ('obj'):
                Group membership handler created by mld_client_add_group
           Returns:
             True
           Raises:
             KeyError
        '''
        grps = self._get_mldclient_field(client_handler.handles[0], 'grps')
        if group_handler not in grps:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        if source_handler not in grps[group_handler]:
            log.error('Group does not exist')
            raise KeyError

        if mem_handler not in grps[group_handler][source_handler]:
            log.error('Source does not exist')
            raise KeyError

        self._trex.emulation_mld_group_config(mode='delete',
                                              handle=mem_handler,
                                              session_handle=client_handler.handles[0])

        del grps[group_handler]
        self._update_mldclient_field(client_handler.handles[0], 'grps', grps)
        return True

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
             True
        '''
        version = self._get_mldclient_field(client_handler.handles[0], 'version')
        if mode == 'start':
            if version == 'v1':
                self._trex.emulation_mld_control(mode='join',
                                                 port_handle=interface)
            else:
                self._trex.emulation_mld_control(mode='start',
                                                 port_handle=interface)
        else:
            grps = self._get_mldclient_field(client_handler.handles[0], 'grps')

            if version == 'v1':
                del_grps_list =[]
                for grp in grps:
                    self._trex.emulation_mld_group_config(mode='modify',
                                                          session_handle=client_handler.handles[0],
                                                          handle=grps[grp]['*'],
                                                          g_action='leave')
                    del_grps_list.append(grp)
                # Send the leave message
                self._trex.emulation_mld_control(port_handle=interface,
                                                 mode='start')
                # Remove the groups membership from the client
                for grp in del_grps_list:
                    self.mld_client_del_group(client_handler, grp, grps[grp]['*'])
                # Restart the updated client
                self._trex.emulation_mld_control(port_handle=interface,
                                                 mode='join')
            else:
                for grp in grps:
                    for src in grps[grp]:
                        self._trex.emulation_mld_group_config(mode='delete',
                                                              handle=grps[grp][src],
                                                              session_handle=client_handler.handles[0])
                        #get filter
                        filt = self.mld_clients[client_handler.handles[0]]['filters'][grps[grp][src]]
                        if filt == 'include':
                            g_filter = 'block_old_source'
                            grp_hdl = self._trex.emulation_mld_group_config(mode='create',
                                                                            session_handle=client_handler.handles[0],
                                                                            group_pool_handle=grp,
                                                                            source_pool_handle='{}/0.0.0.0/1'.format(src),
                                                                            g_filter_mode=g_filter)
                            self._add_mldgroup(src, client_handler.handles[0], grp, grp_hdl.handle)
                            self._update_mld_filter(client_handler.handles[0], grp_hdl.handle, 'block_old_source')
                        else:
                            g_filter = 'change_to_include'
                            grp_hdl = self._trex.emulation_mld_group_config(mode='create',
                                                                            session_handle=client_handler.handles[0],
                                                                            group_pool_handle=grp,
                                                                            g_filter_mode=g_filter)
                            self._add_mldgroup(src, client_handler.handles[0], grp, grp_hdl.handle)
                            self._update_mld_filter(client_handler.handles[0], grps[grp][src], 'change_to_include')

                self._trex.emulation_mld_control(port_handle=interface,
                                                 mode='start')
        return True

    # =============================================================
    # MLD Client management methods
    # Allocate a client key to track all the clients
    # This set of methods used to manage the mld clients of pagent
    # ==============================================================

    def _get_mldclient_hkey(self, interface, vlanid, clientip, version):
        '''Get host key of mld client, create a new key for new client
           Args:
             interface ('str'): interface name
             vlanid ('int'): vlan id
             clientip ('str'): client ip address
             version ('str'): mld version
           Returns:
             Host key of mld client
        '''
        client_hdl = self._trex.emulation_mld_config(mode='create',
                                                     port_handle=interface,
                                                     intf_ip_addr=clientip,
                                                     version=version,
                                                     vlan_id=vlanid)

        if client_hdl.handles[0] not in self.mld_clients:
            self.mld_clients[client_hdl.handles[0]] = {
                'version': version,
                'grps': {},
                'filters': {},
                'interface': interface,
            }

        return client_hdl

    def _del_mldclient_hkey(self, handle):
        '''Delete a mld client host
           Args:
             handle ('str'): mld client host key
           Returns:
             True/False
           Raises:
             None
        '''
        if handle in self.mld_clients:
            del self.mld_clients[handle]
            return True

        return False

    def _update_mldclient_field(self, handle, key, value):
        '''Update mldclient field by host key
           Args:
             handle ('str'): mld client host key
             key ('any'): field key
             value ('any'): field value
           Returns:
             None
           Raises:
             None
        '''
        self.mld_clients[handle][key] = value
        log.info(
            'Client {handle} update: {key}'.format(
                handle=handle, key=key
            )
        )

    def _get_mldclient_field(self, client_hdl, key):
        '''Update igmpclient field by host key
           Args:
             client_hdl ('str'): igmp client host key
             key ('any'): field key
           Returns:
             field value
           Raise:
             KeyError
        '''
        val = self.mld_clients[client_hdl][key]
        if val is None:
            log.warn('Key not in dictionary')
            raise KeyError
        return val

    def _update_mld_filter(self, client, grp_hdl, filter):
        '''Update filter by group member handle
           Args:
             client ('str')
             grp_hdl ('str')
             filter('str')
           Return:
             True
           Raise:
             KeyError
        '''
        if client not in self.mld_clients:
            log.error('Client does not exist')
            raise KeyError
        if grp_hdl not in self.mld_clients[client]['filters']:
            log.error('Group does not exist')
            raise KeyError
        self.mld_clients[client]['filters'][grp_hdl] = filter
        return True

    def _add_mldgroup(self, source_handler, client_handler, group_handler, grp_hdl):
        '''Add mld client to group
           Args:
             source_handler ('str'): source handle key
             client_handler (dictionary): client handle
             group_handler (dictionary): group handle
             grp_hdl (dictionary): group member handle
           Returns:
             True
           Raise:
             KeyError
        '''
        if client_handler not in self.mld_clients:
            raise KeyError
        if group_handler not in self.mld_clients[client_handler]['grps']:
            self.mld_clients[client_handler]['grps'][group_handler]={}
        if not source_handler:
            self.mld_clients[client_handler]['grps'][group_handler]['*']=grp_hdl
        else:
            self.mld_clients[client_handler]['grps'][group_handler][source_handler]=grp_hdl

        '''filter initialization'''
        self.mld_clients[client_handler]['filters'][grp_hdl] = None
        return True

    def enable_subinterface_emulation(self, port, ip, mac):
        '''Enables subinterface emulation on the traffic generator's specified port
            Args:
             port ('int'): Traffic generator's port handle
             ip ('str'): ipv6 address
             mac ('str'): mac address
            Returns:
             Handle of subinterface group
        '''
        status = self._trex.emulation_subinterface_control(
            port_handle=port,
            ip_start = ip,
            mac_start = mac,
        )
        return status.handle

    def disable_subinterface_emulation(self, handle):
        '''Disables subinterface emulation on the traffic generator's specified port
            Args:
             handle ('obj'): Handle of previously created subinterface group
            Returns:
             None
        '''
        self._trex.emulation_subinterface_control(
            mode='remove',
            handle=handle
        )