# ---------------------------------------------------------------------------
# *             This code will only work internally within Cisco
# *              Any attempt to use it externally will fail and
# *                       no support will be provided
# ---------------------------------------------------------------------------

#
# pagent.py
#
# Copyright (c) 2021 by Cisco Systems, Inc.
# All rights reserved.
#
import time
import ipaddress
import logging

from .pagentflow import PG_Manager
from .pagentflow import PG_flow_rawip
from .pagentflow import PG_flow_rawipv6
from .pagentflow import PG_flow_igmpv2_report
from .pagentflow import PG_flow_igmpv3_report
from .pagentflow import PG_flow_igmp_leave
from .pagentflow import PG_flow_mldv1_report
from .pagentflow import PG_flow_mldv1_done
from .pagentflow import PG_flow_mldv2_report
from .pagentflow import PG_flow_arp_request
from .pagentflow import PG_flow_acd_request
from .pagentflow import PG_flow_ndp_ns
from .pagentflow import PG_flow_ndp_na
from .pagentflow import PG_flow_acd_request
from .pagentflow import PG_flow_dhcpv6
from .pagentflow import PG_flow_dhcpv4

# Unicon
from unicon import Connection
from unicon.core.errors import (ConnectionValidationError,
                                ConnectionInfraError,
                                ConnectionError,
                                SpawnInitError,
                                SubCommandFailure)
# Genie
from genie.trafficgen.trafficgen import TrafficGen

# Logger
log = logging.getLogger(__name__)


class Pagent(TrafficGen):
    def __init__(self, *args, **kwargs):
        # Internal variables
        self.igmp_clients = {}
        self.mld_clients = {}
        self.client_seqnum = 1

        self.mcast_grps = {}
        self.mcast_srcs = {}
        self.flows = {}

        super(Pagent, self).__init__(*args, **kwargs)
        self.device = self.device or kwargs.get('device')

        self.via = kwargs.get('via', 'tgn')
        self.pg_flow_name = 'pgf'

        if self.device is not None:
            connection_args = self.device.connections.get(self.via)
        else:
            connection_args = kwargs

        self.ip = connection_args.get('ip')
        self.port = connection_args.get('port')

        self.tg = None

    def connect(self):
        '''Connect to Pagent'''
        if self.tg and self.tg.connected:
            log.info('already connected')
            return

        if self.tg:
            self.tg.connect()
        else:
            try:
                self.tg = Connection(
                    hostname=self.device.name,
                    start=['telnet {ip} {port}'.format(ip=self.ip,
                                                       port=self.port)],
                    os='ios', platform='pagent'
                )
                # Adding device cli attribute for backward compatibility for
                # test cases that use pagent with the traditional
                # execute/configure methods. This allows a pagent device to be
                # specified in the testbed using the genie.trafficgen.TrafficGen
                # class while also exposing some of the unicon methods to the
                # user
                self.device.cli = self.tg
                self.tg.connect()
            except (ConnectionValidationError, ConnectionInfraError,
                    ConnectionError, SpawnInitError, SubCommandFailure) as err:
                log.error('Failed to connect pagent: {e}'.format(e=str(err)))
                return

        self.pg = PG_Manager(self.tg)

    def disconnect(self):
        '''Disconnect from Pagent'''
        self.tg.disconnect()

    @property
    def connected(self):
        if self.tg:
            return self.tg.connected

        return False

    # Adding traditional CLI methods to allow user to use pagent with
    # traditional CLI user interface
    def configure(self, *args, **kwargs):
        return self.tg.configure(*args, **kwargs)

    def execute(self, *args, **kwargs):
        return self.tg.execute(*args, **kwargs)

    def sendline(self, *args, **kwargs):
        return self.tg.sendline(*args, **kwargs)

    def expect(self, *args, **kwargs):
        return self.tg.expect(*args, **kwargs)

    def start_traffic(self, port, wait_time=1,
                      flow_clear=True, start_only=False,
                      start_send=False):
        ''' start_traffic for Pagent, support in three ways:
            1. Execute tgn traffic configuration on pagent based
               on self.flows, and then start traffic decided by transmit_mode
            2. start traffic only without configuring traffics (tgn start)
            3. start traffic only without configuring and to send specified
               number pkts (tgn start send)
            Args:
              port ('str'): interface to send packets on
              wait_time ('int', optional): interval time between each flow
                                           configure and start
              flow_clear ('bool', optional): clear flow argument once started
                                             default True
              start_only ('bool', optional): start traffic without configuring,
                                             default False
              start_send ('bool', optional): use "tgn start send" to start
                                             default False
            Returns:
              None
        '''
        try:
            if not start_only:
                flows = self.flows[port]
                self.pg.start_traffic(port, flows, wait_time)
                if flow_clear:
                    flows.clear()
            else:
                cfg = [
                    f"interface {port}",
                    "no shutdown",
                ]
                self.tg.configure(cfg)
                self.tg.execute('tgn {}'.format(port))
                if start_send:
                    self.tg.execute('tgn start send')
                else:
                    self.tg.execute('tgn start')
        except KeyError:
            log.exception("Traffic streams not configured on port {}".format(port))

    def stop_traffic(self, port, wait_time=1, stop_only=False):
        ''' stop_traffic for Pagent, support in two ways:
            1. stop traffic and delete traffics
            2. stop traffic without deleting traffics
            Args:
              port ('str'): interface to send packets on
              wait_time ('int', optional): sleep time after traffic stopped
              stop_only ('bool', optional): not delete traffic once stopped
                                            default False
            Returns:
              None
        '''
        self.pg.stop_traffic(port, stop_only)
        time.sleep(wait_time)

    def clear_traffic(self):
        ''' clear_traffic for Pagent, tgn clear all
            Returns:
              None
        '''
        self.pg.clear_tgn()

    def modify_traffic(self, port, name, **kwargs):
        ''' modify_traffic for Pagent
            Args:
              port ('str'): interface that traffic to modified on
              name ('str'): traffic name to be modified
              kwargs ('dict'): variables to be modified
            Returns:
              None
        '''
        cmds = []
        for key in kwargs:
            key = key.replace('_','-')
            cmds.extend([
                '{} {}'.format(key, kwargs[key])
            ])
        self.tg.execute('tgn {}'.format(port))
        self.tg.execute('tgn select {}'.format(name))
        for cmd in cmds:
            self.tg.execute('tgn {}'.format(cmd))

    def configure_dhcpv6_request(self, interface, src_mac, requested_ip,
                                cid=None, sid=None, vlan_id=0, xid=0,
                                transmit_mode='single_burst',
                                pkts_per_burst=1, pps=100):
        ''' To use configure_dhcpv6_request for Pagent, you must provide a path to the desired
            template file in the l2iol testbed.yaml file via the "link_files" key
            ex. )   local:
                        link_files: ['%CALLABLE{genie.trafficgen.ios.pagent.utils.get_template_path}/dhcpv6.ptd']
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
        self.pg.load_template('dhcpv6.ptd')
        flow = PG_flow_dhcpv6('dhcpv6_req', src_mac, cid, sid, xid, requested_ip, vlan_id)
        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_dhcpv6_reply(self, interface, src_mac, src_ip,
                               assigned_ip, lease_time, cid=None,
                               sid=None, vlan_id=0, xid=0,
                               transmit_mode='single_burst',
                               pkts_per_burst=1, pps=100):
        ''' To use configure_dhcpv6_reply for Pagent, you must provide a path to the desired
            template file in the l2iol testbed.yaml file via the "link_files" key
            ex. )   local:
                        link_files: ['%CALLABLE{genie.trafficgen.ios.pagent.utils.get_template_path}/dhcpv6.ptd']
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
        self.pg.load_template('dhcpv6.ptd')
        flow = PG_flow_dhcpv6('dhcpv6_rep', src_mac, cid, sid, xid, None, src_ip, assigned_ip, lease_time, vlan_id)
        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_arp_request(self, port, mac_src, ip_src, ip_dst, frame_size=60,
                              vlan_id=0, transmit_mode='single_burst',
                              pkts_per_burst=1, pps=100):

        flow = PG_flow_arp_request('arpreq', mac_src, ip_src, ip_dst, vlan_tag=vlan_id)
        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(port, [])
        flows.append(flow)

    def configure_garp(self, port, mac_src, ip, frame_size=60,
                       vlan_id=0, transmit_mode='single_burst',
                       pkts_per_burst=1, pps=100):

        flow = PG_flow_arp_request('garp', mac_src, ip, ip, vlan_tag=vlan_id)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(port, [])
        flows.append(flow)

    def configure_acd(self, port, mac_src, ip_dst, frame_size=60,
                      vlan_id=0, transmit_mode='single_burst',
                      pkts_per_burst=1, pps=100):

        flow = PG_flow_acd_request('acd', mac_src, ip_dst, vlan_tag=vlan_id)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(port, [])
        flows.append(flow)

    def configure_dhcpv4_request(self, interface, mac_src, requested_ip, xid=0,
                                 transmit_mode='single_burst', pkts_per_burst=1, pps=100):
        ''' To use configure_dhcpv4_request for Pagent, you must provide a path to the desired
            template file in the l2iol testbed.yaml file via the "link_files" key
            ex. )   local:
                        link_files: ['%CALLABLE{genie.trafficgen.ios.pagent.utils.get_template_path}/dhcpv4.ptd']
            Args:
              interface ('int'): port to configure stream
              mac_src ('str'): source mac address
              requested_ip ('str'): requested ip address
              xid ('int', optional): transaction id, default 0
              transmit_mode ('str', optional): ('continuous', 'multi_burst', 'single_burst'), default single_burst
              pkts_per_burst ('int', optional): packets per burst, default 1
              pps ('int', optional): packets per second, default 100
        '''
        self.pg.load_template('dhcpv4.ptd')
        flow = PG_flow_dhcpv4('dhcpv4_request', mac_src, xid, requested_ip=requested_ip)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_dhcpv4_reply(self, interface, mac_src, ip_src, assigned_ip,
                               lease_time, xid=0, transmit_mode='single_burst',
                               pkts_per_burst=1, pps=100):
        ''' To use configure_dhcpv4_reply for Pagent, you must provide a path to the desired
            template file in the l2iol testbed.yaml file via the "link_files" key
            ex. )   local:
                        link_files: ['%CALLABLE{genie.trafficgen.ios.pagent.utils.get_template_path}/dhcpv4.ptd']
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
        '''
        self.pg.load_template('dhcpv4.ptd')
        flow = PG_flow_dhcpv4('dhcpv4_reply', mac_src, xid, ip_src=ip_src, assigned_ip=assigned_ip,
                              lease_time=lease_time)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_ns(self, interface, mac_src, ip_src, ip_dst, hop_limit=255,
                     length_mode='auto', vlan_id=0, transmit_mode='single_burst',
                     pkts_per_burst=1, pps=100):
        flow = PG_flow_ndp_ns('ndpns', mac_src, ip_src, ip_dst, vlan_tag=vlan_id,
                              hop_limit=hop_limit, length_mode=length_mode)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_na(self, interface, mac_src, ip_src, ip_dst, solicited=True,
                     hop_limit=255, length_mode='auto', vlan_id=0,
                     transmit_mode='single_burst', pkts_per_burst=1, pps=100):

        if solicited:
            l3target_full = ipaddress.IPv6Address(ip_dst).exploded
            low24 = l3target_full[32:]
            mac_dst = '3333.ff{}.{}'.format(low24[0:2], low24[3:])
        else:
            ip_dst = "FF02::1"
            mac_dst = "0000.0000.0000"

        flow = PG_flow_ndp_na('ndpna', mac_src, mac_dst, ip_src, ip_dst, vlan_tag=vlan_id,
                              hop_limit=hop_limit, length_mode=length_mode)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_dad(self, interface, mac_src, ip_dst, hop_limit=255,
                      length_mode='auto', vlan_id=0, transmit_mode='single_burst',
                      pkts_per_burst=1, pps=100):
        flow = PG_flow_ndp_ns('ndpdad', mac_src, "::", ip_dst, vlan_tag=vlan_id,
                              hop_limit=hop_limit, length_mode=length_mode)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        flows = self.flows.setdefault(interface, [])
        flows.append(flow)

    def configure_rawip(self, interface, name, mac_src, mac_dst,
                        ip_src, ip_dst,
                        vlan_tag=0, data_length=18,
                        transmit_mode='single_burst',
                        pkts_per_burst=1, pps=100, configure=False,
                        **kwargs):
        ''' To create pagent raw ipv4 flows and configure those
            traffics on pagent (optional)
            Args:
              interface ('str'): interface to configure traffic on
              name ('str'): traffic name to be configured
              mac_src ('str'): traffic source mac address
              mac_dst ('str'): traffic destination mac address
              ip_src ('str'): traffic source ipv4 address
              ip_dst ('str'): traffic destination ipv4 address
              vlan_tag ('int', optional): traffic vlan tag
              data_length ('int', optional): l3 data length
              transmit_mode ('str', optional): traffic transimit mode
              pkts_per_burst: ('int', optional): single burst packets number
              pps ('int', optional): traffic send rate
              configure ('bool', optional): configure on pagent once created
                                            default False
            Returns:
              None
        '''
        flow = PG_flow_rawip(name, mac_src, mac_dst, ip_src, ip_dst,
                             vlan_tag=vlan_tag, data_length=data_length,
                             **kwargs)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        if interface not in self.flows:
            flows = self.flows.setdefault(interface, [])
        else:
            flows = self.flows[interface]

        flows.append(flow)
        if configure:
            self.pg.configure_traffic(interface, flow)

    def configure_rawipv6(self, interface, name, mac_src, mac_dst,
                        ipv6_src, ipv6_dst,
                        vlan_tag=0, data_length=18,
                        transmit_mode='single_burst',
                        pkts_per_burst=1, pps=100, configure=False,
                        **kwargs):
        ''' To create pagent raw ipv6 flows and configure those
            traffics on pagent (optional)
            Args:
              interface ('str'): interface to configure traffic on
              name ('str'): traffic name to be configured
              mac_src ('str'): traffic source mac address
              mac_dst ('str'): traffic destination mac address
              ipv6_src ('str'): traffic source ipv4 address
              ipv6_dst ('str'): traffic destination ipv4 address
              vlan_tag ('int', optional): traffic vlan tag
              data_length ('int', optional): l3 data length
              transmit_mode ('str', optional): traffic transimit mode
              pkts_per_burst: ('int', optional): single burst packets number
              pps ('int', optional): traffic send rate
              configure ('bool', optional): configure on pagent once created
                                            default False
            Returns:
              None
        '''
        flow = PG_flow_rawipv6(name, mac_src, mac_dst, ipv6_src, ipv6_dst,
                               vlan_tag=vlan_tag, data_length=data_length,
                               **kwargs)

        flow.set_transmit_settings(transmit_mode, pkts_per_burst, pps)

        if interface not in self.flows:
            flows = self.flows.setdefault(interface, [])
        else:
            flows = self.flows[interface]

        flows.append(flow)
        if configure:
            self.pg.configure_traffic(interface, flow)

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
        flow = PG_flow_rawip('tg_ip', mac_src, mac_dst,
                             ip_src, ip_dst, vlanid)
        self.pg.send_traffic(flow, interface, pps, count)
        self.pg.clear_tgn()
        return True

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
        '''
        self.pg.clear_pkts()
        expected_flow = PG_flow_rawip(self.pg_flow_name, mac_src, mac_dst,
                                      ip_src, ip_dst, vlan_tag)

        ports = interface if isinstance(interface, list) else [interface]

        for intf in ports:
            self.pg.add_fastcount_filter(expected_flow, intf)

        self.pg.start_pkts_count()

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
        '''
        flow = PG_flow_rawipv6('ipv6', mac_src, mac_dst, ipv6_src, ipv6_dst, vlanid)
        self.pg.send_traffic(flow, interface, pps, count)
        self.pg.clear_tgn()

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
        '''
        self.pg.clear_pkts()
        expected_flow = PG_flow_rawipv6(self.pg_flow_name, mac_src, mac_dst,
                                        ipv6_src, ipv6_dst, vlan_tag)

        ports = interface if isinstance(interface, list) else [interface]

        for intf in ports:
            self.pg.add_fastcount_filter(expected_flow, intf)
        self.pg.start_pkts_count()

    def stop_pkt_count(self, interface):
        '''Stop ip packet count
           Args:
             interface ('str' or 'list'): interface name
                                  or list of interface names
                                  shall be same as passed in start_pkt_count
           Returns:
             None
        '''
        self.pg.stop_pkts_count()

    def get_pkt_count(self, interface):
        '''Get ip packet count
           Args:
             interface ('str'): interface name
           Returns:
             count('int')
        '''
        packet_count = self.pg.get_fastcount(self.pg_flow_name, interface)
        return packet_count

    def start_pkt_count_rawip_mcast(self, interface, mac_src,
                                    ip_src, ip_dst, vlan=0):
        '''Start ip packet count mcast
           Args:
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
        self.start_pkt_count_rawip(interface, mac_src,
                                   mac_dst, ip_src, ip_dst, vlan)

    def send_rawip_mcast(self, interface, mac_src, ip_src, ip_dst,
                         vlan=0, count=1, pps=100):
        '''Start ip packet count mcast
           Args:
             mac_src ('str'): source mac address, example aabb.bbcc.ccdd
             ip_src ('str'): source ip address
             ip_dst ('str'): destination ip address
             vlan ('int', optional): vlan id, default is 0
             count ('int', optional): number of ip pkt send, default is 1
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
        flow = PG_flow_arp_request('arpreq', mac_src, ip_src, ip_target,
                                   vlan_tag=vlan_tag)
        self.pg.send_traffic(flow, interface, pps, count)
        self.pg.clear_tgn()

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
        flow = PG_flow_ndp_ns('ndpns', mac_src, ip_src, ip_dst,
                              vlan_tag=vlan_tag)
        self.pg.send_traffic(flow, interface, pps, count)
        self.pg.clear_tgn()

    def send_ndp_na(self, interface, mac_src, mac_dst, ip_src, ip_dst,
                    vlan_tag=0, count=1, pps=100):
        '''Send ndp neighbor advertisement packet
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
        flow = PG_flow_ndp_na('ndpna', mac_src, mac_dst, ip_src, ip_dst,
                              vlan_tag=vlan_tag)
        self.pg.send_traffic(flow, interface, pps, count)
        self.pg.clear_tgn()

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
             None
        '''
        grpkey = self._get_ippoolkey(groupip, inc_steps, group_nums)
        if grpkey in self.mcast_grps:
            log.warn('Multicast Group {} has been created'.format(groupip))
            return grpkey

        addr_max = self._get_ippoolmax(groupip, inc_steps, group_nums)
        self.mcast_grps[grpkey] = {
            'grp_ip': groupip,
            'steps': inc_steps,
            'pref_len': ip_prefix_len,
            'grp_num': group_nums,
            'grp_max': str(addr_max),
        }
        return grpkey

    def delete_multicast_group(self, group_handler):
        '''delete multicast group pool
           Args:
             group_handler ('obj'): multicast group pool handler
           Returns:
             True/False
           Raises:
             None
        '''
        grpkey = group_handler
        if grpkey in self.mcast_grps:
            del self.mcast_grps[grpkey]
            return True

        return False

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
             None
        '''
        srckey = self._get_ippoolkey(sourceip, inc_steps, source_nums)
        if srckey in self.mcast_srcs:
            log.warn('Multicast Source {} has been created'.format(sourceip))
            return srckey

        addr_max = self._get_ippoolmax(sourceip, inc_steps, source_nums)
        self.mcast_srcs[srckey] = {
            'src_ip': sourceip,
            'steps': inc_steps,
            'pref_len': ip_prefix_len,
            'src_num': source_nums,
            'src_max': str(addr_max),
        }
        return srckey

    def delete_multicast_source(self, source_handler):
        '''delete multicast source pool
           Args:
             source_handler ('obj'): multicast source pool handler
           Returns:
             True/False
           Raises:
             None
        '''
        srckey = source_handler
        if srckey in self.mcast_srcs:
            del self.mcast_srcs[srckey]
            return True

        return False

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
             None
        '''
        hkey = self._get_igmpclient_hkey(interface, vlanid, clientip)

        self._update_igmpclient_field(hkey, 'version', version)
        self._update_igmpclient_field(hkey, 'vlan', vlanid)

        return hkey

    def delete_igmp_client(self, client_handler):
        '''Delete IGMP Client
           Args:
             client_handler ('obj'): IGMP Client handler
           Returns:
             True/False
           Raises:
             None
        '''
        hkey = client_handler
        return self._del_igmpclient_hkey(hkey)

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
             None
        '''

        hkey = client_handler
        gkey = group_handler
        skey = source_handler

        # generate group membership handler
        handle = "{client}:{grp}:{src}".format(client=hkey, grp=gkey,
                                               src=str(skey))

        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            grps.append(gkey)
            grp_attr[gkey] = {}

        grp_attr[gkey][str(skey)] = {
            'fmode': filter_mode,
        }

        self._update_igmpclient_field(hkey, 'grps', grps)
        self._update_igmpclient_field(hkey, 'grp_attr', grp_attr)

        return handle

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
             KeyError
        '''
        hkey, gkey, skey = handler.split(':')
        if hkey != client_handler:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            log.error('Group not exist')
            raise KeyError

        version = self._get_igmpclient_field(hkey, 'version')
        if version != 3 or grp_attr[gkey][skey]['fmode'] == filter_mode:
            # Not supported operation
            log.error(
                'Not supported operation: change client {hkey} from '
                'version {ver} {fmode} mode to {upd_fmode}'.format(
                    hkey=hkey, ver=version,
                    fmode=grp_attr[gkey][skey]['fmode'],
                    upd_fmode=filter_mode,
                )
            )
            return

        # Modify the filter mode
        grp_attr[gkey][skey]['fmode'] = filter_mode
        self._update_igmpclient_field(hkey, 'grp_attr', grp_attr)

        interface, client_ip = hkey.split(',')
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        # Pagent TGN does not support igmpv3 template
        # the implementation is actually a hack using igmpv1 format
        # it only supports one group record for now
        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']
        src_num = self.mcast_srcs[skey]['src_num']
        src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                        self.mcast_srcs[skey]['steps'],
                                        src_num)

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 3
        else:
            mode = 4

        flow = PG_flow_igmpv3_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

        return handler

    def igmp_client_del_group(self, client_handler, handler):
        '''IGMP Client delete group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
           Returns:
             True/False
           Raises:
             KeyError
        '''
        hkey, gkey, skey = handler.split(':')
        if hkey != client_handler:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        # Remove the group from client
        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            log.error('Group not exist')
            raise KeyError

        del grp_attr[gkey][skey]
        # If all source handler removed, then remove
        # then group handler membership as well
        if not grp_attr[gkey]:
            grps.remove(gkey)
            del grp_attr[gkey]

        self._update_igmpclient_field(hkey, 'grps', grps)
        self._update_igmpclient_field(hkey, 'grp_attr', grp_attr)

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
             True/False
           Raises:
             None
        '''
        hkey = client_handler

        if mode == 'start':
            self._start_igmpclient(hkey)

        elif mode == 'stop':
            self._stop_igmpclient(hkey)

        elif mode == 'restart':
            # Fake restart, simply re-sent join message.
            self._start_igmpclient(hkey)

        else:
            return False

        return True

    # MLD APIs
    def create_mld_client(self, interface, clientip, version, vlanid=0):
        '''Create MLD Client
           Args:
             interface ('str'): interface name
             clientip ('str'): ip address
             version ('int'): 1 or 2
             vlanid ('int'): vlan id, default = 0
           Returns:
             mld client handler
        '''
        hkey = self._get_mldclient_hkey(interface, vlanid, clientip)

        self._update_mldclient_field(hkey, 'version', version)
        self._update_mldclient_field(hkey, 'vlan', vlanid)

        return hkey

    def delete_mld_client(self, client_handler):
        '''Delete MLD Client
           Args:
             client_handler ('obj'): MLD Client handler
           Returns:
             True/False
        '''
        hkey = client_handler
        return self._del_mldclient_hkey(hkey)

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
             should be None, filter_mode should be exclude
           Returns:
             group membership handler
        '''

        hkey = client_handler
        gkey = group_handler
        skey = source_handler

        # generate group membership handler
        handle = "{client}%{grp}%{src}".format(client=hkey, grp=gkey,
                                               src=str(skey))

        grps = self._get_mldclient_field(hkey, 'grps')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            grps.append(gkey)
            grp_attr[gkey] = {}

        grp_attr[gkey][str(skey)] = {
            'fmode': filter_mode,
        }

        self._update_mldclient_field(hkey, 'grps', grps)
        self._update_mldclient_field(hkey, 'grp_attr', grp_attr)

        return handle

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
        '''
        hkey, gkey, skey = handler.split('%')
        if hkey != client_handler:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        grps = self._get_mldclient_field(hkey, 'grps')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            log.error('Group not exist')
            raise KeyError

        version = self._get_mldclient_field(hkey, 'version')
        if version != 2 or grp_attr[gkey][skey]['fmode'] == filter_mode:
            # Not supported operation
            log.error(
                'Not supported operation: change client {hkey} from '
                'version {ver} {fmode} mode to {upd_fmode}'.format(
                    hkey=hkey, ver=version,
                    fmode=grp_attr[gkey][skey]['fmode'],
                    upd_fmode=filter_mode,
                )
            )
            return

        # Modify the filter mode
        grp_attr[gkey][skey]['fmode'] = filter_mode
        self._update_mldclient_field(hkey, 'grp_attr', grp_attr)

        interface, client_ip = hkey.split(',')
        vlan = self._get_mldclient_field(hkey, 'vlan')

        # Pagent TGN does not support mldv2 template
        # the implementation is actually a hack using mldv1 format
        # it only supports one group record for now
        c_name = self._get_mldclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']
        src_num = self.mcast_srcs[skey]['src_num']
        src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                        self.mcast_srcs[skey]['steps'],
                                        src_num)

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 3
        else:
            mode = 4

        flow = PG_flow_mldv2_report(c_name, smac, client_ip, group,
                                    src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

        return handler

    def mld_client_del_group(self, client_handler, handler):
        '''MLD Client delete group membership
           Args:
             client_handler ('obj'): MLD Client handler
             handler ('obj'):
                Group membership handler created by mld_client_add_group
           Returns:
             True/False
           Raises:
             KeyError
        '''
        hkey, gkey, skey = handler.split('%')
        if hkey != client_handler:
            log.error('Client handler and Membership handler mismatch')
            raise KeyError

        # Remove the group from client
        grps = self._get_mldclient_field(hkey, 'grps')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')
        if gkey not in grps:
            log.error('Group not exist')
            raise KeyError

        del grp_attr[gkey][skey]
        # If all source handler removed, then remove
        # then group handler membership as well
        if not grp_attr[gkey]:
            grps.remove(gkey)
            del grp_attr[gkey]

        self._update_mldclient_field(hkey, 'grps', grps)
        self._update_mldclient_field(hkey, 'grp_attr', grp_attr)

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
             True/False
        '''
        hkey = client_handler

        if mode == 'start':
            self._start_mldclient(hkey)

        elif mode == 'stop':
            self._stop_mldclient(hkey)

        elif mode == 'restart':
            # Fake restart, simply re-sent join message.
            self._start_mldclient(hkey)

        else:
            return False

        return True

    # ==============================================================
    # ip pool methods
    # ==============================================================
    def _get_ippoolkey(self, ip, steps, num):
        '''get the key of ip pool
           Args:
             ip ('str'): start ip address of the ip pool
             steps ('str'): increment step ip address of the ip pool
             num ('int'): address number of the ip pool
           Returns:
             the key of ip pool
           Raises:
             None
        '''
        return "{ip}_{steps}_{num}".format(ip=ip, steps=steps, num=num)

    def _get_ippoolmax(self, ip, steps, num):
        '''get the max address of the ip pool
           Args:
             ip ('str'): start ip address of the ip pool
             steps ('str'): increment step ip address of the ip pool
             num ('int'): address number of the ip pool
           Returns:
             the maximum address of ip pool
           Raises:
             None
        '''
        addr_ip = ipaddress.ip_address(ip)
        addr_inc = int(num) * int(ipaddress.ip_address(steps))
        addr_max = addr_ip + addr_inc
        return addr_max

    def _get_ippool_ips(self, ip, steps, num):
        '''get a list of ips of the ip pool
           Args:
             ip ('str'): start ip address of the ip pool
             steps ('str'): increment step ip address of the ip pool
             num ('int'): address number of the ip pool
           Returns:
             List of ips of ip pool
           Raises:
             None
        '''
        ip_start = ipaddress.ip_address(ip)
        ip_steps = ipaddress.ip_address(steps)
        ip_list = []
        # making src list
        for x in range(0, num):
            ip = ip_start + int(x) * int(ip_steps)
            ip_list.append(str(ip))

        return ip_list

    # =============================================================
    # IGMP Client management methods
    # Allocate a clientkey to track all the clients
    # This set of methods used to manage the igmp clients of pagent
    # ==============================================================
    def _get_igmpclient_hkey(self, interface, vlanid, clientip):
        '''Get host key of igmp client, create a new key for new client
           Args:
             interface ('str'): interface name
             vlanid ('int'): vlan id
             clientip ('str'): client ip address
           Returns:
             Host key of igmp client
           Raises:
             SubCommandFailure
        '''
        intf = interface

        # For Pagent, by default, vlan id is not supported in ICE
        # We need to create Ethernet subinterface for vlan encapsulation
        if intf not in self.igmp_clients:
            self.igmp_clients[intf] = {}
            try:
                # always no shutdown the main interface
                self.tg.configure(
                    [
                        'interface {intf}'.format(intf=interface),
                        'no shutdown',
                    ]
                )
            except SubCommandFailure:
                raise SubCommandFailure(
                    "Failed to no shutdown interface {intf}".format(
                        intf=interface
                    )
                )

        hkey = "{intf},{clientip}".format(intf=intf, clientip=clientip)
        if hkey not in self.igmp_clients[intf]:
            self.igmp_clients[intf][hkey] = {
                'name': 'c_{seq}'.format(seq=self.client_seqnum),
                # client state: idle | running
                # idle: client stopped/left
                # running: client running
                'state': 'idle',
                # group records
                'grps': [],
                'grp_attr': {},
            }
            self.client_seqnum = self.client_seqnum + 1
            log.info(
                'Client {hkey} created: {fields}'.format(
                    hkey=hkey,
                    fields=str(self.igmp_clients[intf][hkey])
                )
            )

        return hkey

    def _del_igmpclient_hkey(self, hkey):
        '''Delete a igmp client host key
           Args:
             hkey ('str'): igmp client host key
           Returns:
             True/False
           Raises:
             True/False
        '''
        intf, ip = hkey.split(',')
        if hkey in self.igmp_clients[intf]:
            del self.igmp_clients[intf][hkey]
            log.info(
                'Client {hkey} deleted'.format(
                    hkey=hkey
                )
            )
            return True

        return False

    def _update_igmpclient_field(self, hkey, key, value):
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
        intf, ip = hkey.split(',')
        self.igmp_clients[intf][hkey][key] = value
        log.info(
            'Client {hkey} update: {key}: {value}'.format(
                hkey=hkey, key=key, value=value
            )
        )

    def _get_igmpclient_field(self, hkey, key):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
           Returns:
             field value
           Raises:
             KeyError
        '''
        intf, ip = hkey.split(',')
        if key == 'interface':
            return intf
        elif key == 'ip':
            return ip
        else:
            return self.igmp_clients[intf][hkey][key]

    def _start_igmpclient(self, hkey):
        '''Start a igmp client
           Args:
             hkey ('str'): host key of igmp client
           Returns:
             None
        '''
        version = self._get_igmpclient_field(hkey, 'version')
        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')

        if version == 2:
            for gkey in grps:
                self._tgn_send_igmpv2join(hkey, gkey)
        elif version == 3:
            for gkey in grps:
                for skey in grp_attr[gkey]:
                    self._tgn_send_igmpv3join(hkey, gkey, skey)
        self._update_igmpclient_field(hkey, 'state', 'running')

    def _stop_igmpclient(self, hkey):
        '''Stop a igmp client
           Args:
             hkey ('str'): host key of igmp client
           Returns:
             None
        '''
        version = self._get_igmpclient_field(hkey, 'version')
        grps = self._get_igmpclient_field(hkey, 'grps')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')

        if version == 2:
            for gkey in grps:
                self._tgn_send_igmpv2leave(hkey, gkey)
        elif version == 3:
            for gkey in grps:
                for skey in grp_attr[gkey]:
                    self._tgn_send_igmpv3leave(hkey, gkey, skey)

        self._update_igmpclient_field(hkey, 'state', 'idle')

        # after receiving leave message, igmp snooping will
        # send queries and wait for response
        # we send dummy join messages to pretend a real igmp client
        time.sleep(2)
        intf, ip = hkey.split(',')
        for host in self.igmp_clients[intf]:
            if self._get_igmpclient_field(host, 'state') == 'running':
                self._start_igmpclient(host)

    # =============================================================
    # MLD Client management methods
    # Allocate a clientkey to track all the clients
    # This set of methods used to manage the mld clients of pagent
    # ==============================================================

    def _get_mldclient_hkey(self, interface, vlanid, clientip):
        '''Get host key of mld client, create a new key for new client
           Args:
             interface ('str'): interface name
             vlanid ('int'): vlan id
             clientip ('str'): client ipv6 address
           Returns:
             Host key of mld client
           Raises:
             SubCommandFailure
        '''
        intf = interface

        # For Pagent, by default, vlan id is not supported in ICE
        # We need to create Ethernet subinterface for vlan encapsulation
        if intf not in self.mld_clients:
            self.mld_clients[intf] = {}
            try:
                # always no shutdown the main interface
                self.tg.configure(
                    [
                        'interface {intf}'.format(intf=interface),
                        'no shutdown',
                    ]
                )
            except SubCommandFailure:
                raise SubCommandFailure(
                    "Failed to no shutdown interface {intf}".format(
                        intf=interface
                    )
                )

        hkey = "{intf},{clientip}".format(intf=intf, clientip=clientip)
        if hkey not in self.mld_clients[intf]:
            self.mld_clients[intf][hkey] = {
                'name': 'c_{seq}'.format(seq=self.client_seqnum),
                # client state: idle | running
                # idle: client stopped/left
                # running: client running
                'state': 'idle',
                # group records
                'grps': [],
                'grp_attr': {},
            }
            self.client_seqnum = self.client_seqnum + 1
            log.info(
                'Client {hkey} created: {fields}'.format(
                    hkey=hkey,
                    fields=str(self.mld_clients[intf][hkey])
                )
            )

        return hkey

    def _del_mldclient_hkey(self, hkey):
        '''Delete a mld client host key
           Args:
             hkey ('str'): mld client host key
           Returns:
             True/False
           Raises:
             None
        '''
        intf, ip = hkey.split(',')
        if hkey in self.mld_clients[intf]:
            del self.mld_clients[intf][hkey]
            log.info(
                'Client {hkey} deleted'.format(
                    hkey=hkey
                )
            )
            return True

        return False

    def _update_mldclient_field(self, hkey, key, value):
        '''Update mldclient field by host key
           Args:
             hkey ('str'): mld client host key
             key ('any'): field key
             value ('any'): field value
           Returns:
             None
           Raises:
             None
        '''
        intf, ip = hkey.split(',')
        self.mld_clients[intf][hkey][key] = value
        log.info(
            'Client {hkey} update: {key}: {value}'.format(
                hkey=hkey, key=key, value=value
            )
        )

    def _get_mldclient_field(self, hkey, key):
        '''Update mldclient field by host key
           Args:
             hkey ('str'): mld client host key
             key ('any'): field key
           Returns:
             field value
           Raises:
             KeyError
        '''
        intf, ip = hkey.split(',')
        if key == 'interface':
            return intf
        elif key == 'ip':
            return ip
        else:
            return self.mld_clients[intf][hkey][key]

    def _start_mldclient(self, hkey):
        '''Start a mld client
           Args:
             hkey ('str'): host key of mld client
           Returns:
             None
        '''
        version = self._get_mldclient_field(hkey, 'version')
        grps = self._get_mldclient_field(hkey, 'grps')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')

        if version == 1:
            for gkey in grps:
                self._tgn_send_mldv1join(hkey, gkey)
        elif version == 2:
            for gkey in grps:
                for skey in grp_attr[gkey]:
                    self._tgn_send_mldv2join(hkey, gkey, skey)
        self._update_mldclient_field(hkey, 'state', 'running')

    def _stop_mldclient(self, hkey):
        '''Stop a mld client
           Args:
             hkey ('str'): host key of mld client
           Returns:
             None
        '''
        version = self._get_mldclient_field(hkey, 'version')
        grps = self._get_mldclient_field(hkey, 'grps')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')

        if version == 1:
            for gkey in grps:
                self._tgn_send_mldv1leave(hkey, gkey)
        elif version == 2:
            for gkey in grps:
                for skey in grp_attr[gkey]:
                    self._tgn_send_mldv2leave(hkey, gkey, skey)

        self._update_mldclient_field(hkey, 'state', 'idle')

        # after receiving leave message, mld snooping will
        # send queries and wait for response
        # we send dummy join messages to pretend a real mld client
        time.sleep(2)
        intf, ip = hkey.split(',')
        for host in self.mld_clients[intf]:
            if self._get_mldclient_field(host, 'state') == 'running':
                self._start_mldclient(host)

    # ======================================================
    # Pagent ICE is not used because of following limitations:
    # 1. Client is managed per interface
    # 2. Client id is the sequence number in the client queue
    # 3. Client id will be dynamically changed if the client queue is modified
    #    when a client is removed from the queue
    # 4. No IGMP configuration is allowed when igmp client is running on the
    #    interface
    # 5. IGMPv3 Client support multiple group records, but pagent does not
    #    support update specific record, only choice is delete then add
    # 6. If multiple IGMPv3 clients exist on same interface, we can stop
    #    a specific client, but restart will possible start all clients
    # 7. IGMPv2 Leave message is illegal, whose destination mac is mapped using
    #    igmp group ip not destination ip.
    # 8. ICE does not support vlan id, but we can use subinteface for vlan
    #    encapsulation
    # 9. Pagent crashes after performing several stop/start action on multiple
    #    ICE igmpv3 client
    # ======================================================

    # ======================================================
    # Pagent TGN APIs
    # ======================================================
    def _tgn_client_mac_by_ip(self, ip):
        '''Generate a unique mac by ip address
           Args:
             ip ('str'): ip address
           Returns:
             mac address
        '''
        map_addr = int(ipaddress.ip_address(ip))
        map_addr = map_addr & 0x7FFFFF
        mac = 'aabb.bb%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        return mac

    def _tgn_send_igmpv2join(self, hkey, gkey):
        '''Simulate sending a igmpv2 join message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv2 join for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')

        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)
        group = self.mcast_grps[gkey]['grp_ip']
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        flow = PG_flow_igmpv2_report(c_name, smac, client_ip, group, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_igmpv2leave(self, hkey, gkey):
        '''Simulate sending a igmpv2 leave message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv2 leave for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)
        group = self.mcast_grps[gkey]['grp_ip']
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        flow = PG_flow_igmp_leave(c_name, smac, client_ip, group, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_igmpv3join(self, hkey, gkey, skey):
        '''Simulate sending a igmpv3 join message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
             skey ('str'): source key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv3 join for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        vlan = self._get_igmpclient_field(hkey, 'vlan')
        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']

        if skey == "None":
            src_num = 0
            src_list = []
        else:
            src_num = self.mcast_srcs[skey]['src_num']
            src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                            self.mcast_srcs[skey]['steps'],
                                            src_num)

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 1
        else:
            mode = 2

        flow = PG_flow_igmpv3_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_igmpv3leave(self, hkey, gkey, skey):
        '''Simulate sending a igmpv3 leave message from specified host
           Args:
             hkey ('str'): host key of igmp client
             gkey ('str'): group key of igmp group member
             skey ('str'): source key of igmp group member
           Returns:
             None
        '''
        log.info('TGN send igmpv3 leave for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        grp_attr = self._get_igmpclient_field(hkey, 'grp_attr')
        vlan = self._get_igmpclient_field(hkey, 'vlan')

        c_name = self._get_igmpclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 6
            src_num = self.mcast_srcs[skey]['src_num']
            src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                            self.mcast_srcs[skey]['steps'],
                                            src_num)
        else:
            mode = 3
            src_num = 0
            src_list = []

        flow = PG_flow_igmpv3_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_mldv1join(self, hkey, gkey):
        '''Simulate sending a mldv1 join message from specified host
           Args:
             hkey ('str'): host key of mld client
             gkey ('str'): group key of mld group member
           Returns:
             None
        '''
        log.info('TGN send mldv1 join for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')

        c_name = self._get_mldclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)
        group = self.mcast_grps[gkey]['grp_ip']
        vlan = self._get_mldclient_field(hkey, 'vlan')

        flow = PG_flow_mldv1_report(c_name, smac, client_ip, group, group, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_mldv1leave(self, hkey, gkey):
        '''Simulate sending a mldv1 leave message from specified host
           Args:
             hkey ('str'): host key of mld client
             gkey ('str'): group key of mld group member
           Returns:
             None
        '''
        log.info('TGN send mldv1 leave for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        c_name = self._get_mldclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)
        group = self.mcast_grps[gkey]['grp_ip']
        vlan = self._get_mldclient_field(hkey, 'vlan')

        flow = PG_flow_mldv1_done(c_name, smac, client_ip, group, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_mldv2join(self,  hkey, gkey, skey):
        '''Simulate sending a mldv2 join message from specified host
           Args:
             hkey ('str'): host key of mld client
             gkey ('str'): group key of mld group member
             skey ('str'): source key of mld group member
           Returns:
             None
        '''
        log.info('TGN send mldv2 join for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')
        vlan = self._get_mldclient_field(hkey, 'vlan')
        c_name = self._get_mldclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']

        if skey == "None":
            src_num = 0
            src_list = []
        else:
            src_num = self.mcast_srcs[skey]['src_num']
            src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                            self.mcast_srcs[skey]['steps'],
                                            src_num)

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 1
        else:
            mode = 2

        flow = PG_flow_mldv2_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()

    def _tgn_send_mldv2leave(self, hkey, gkey, skey):
        '''Simulate sending a mldv2 leave message from specified host
           Args:
             hkey ('str'): host key of mld client
             gkey ('str'): group key of mld group member
             skey ('str'): source key of mld group member
           Returns:
             None
        '''
        log.info('TGN send mldv2 leave for client {hkey}'.format(hkey=hkey))
        interface, client_ip = hkey.split(',')
        grp_attr = self._get_mldclient_field(hkey, 'grp_attr')
        vlan = self._get_mldclient_field(hkey, 'vlan')

        c_name = self._get_mldclient_field(hkey, 'name')
        smac = self._tgn_client_mac_by_ip(client_ip)

        group = self.mcast_grps[gkey]['grp_ip']

        if grp_attr[gkey][skey]['fmode'] == 'include':
            mode = 6
            src_num = self.mcast_srcs[skey]['src_num']
            src_list = self._get_ippool_ips(self.mcast_srcs[skey]['src_ip'],
                                            self.mcast_srcs[skey]['steps'],
                                            src_num)
        else:
            mode = 3
            src_num = 0
            src_list = []

        flow = PG_flow_mldv2_report(c_name, smac, client_ip, group,
                                     src_num, src_list, mode, vlan)
        self.pg.send_traffic(flow, interface, 1, 1)
        self.pg.clear_tgn()
