#---------------------------------------------------------------------------
# *             This code will only work internally within Cisco
# *              Any attempt to use it externally will fail and
# *                       no support will be provided
#---------------------------------------------------------------------------
#
# pagent.py
#
# Jan. 2021
#
# Copyright (c) 2021 by cisco Systems, Inc.
# All rights reserved.

import ipaddress
import re
import time
from .utils import make_link_local_ipv6, make_multicast_mac, convert_ip_to_int, pad_hex_num
#
# Import modules used.
#

igmp_query_dstip = '224.0.0.1'
igmp_leave_dstip = '224.0.0.2'
igmpv3_report_dstip = '224.0.0.22'


class PG_flow_t(object):
    def __init__(self, template, name):
        self.__template = template
        self.__flow_name = name
        self.transmit_settings = {'transmit_mode': None, 'pkts_per_burst': None, 'pps': None}

    def get_template(self):
        return self.__template

    def get_name(self):
        return self.__flow_name

    def get_config(self):
        raise NotImplementedError

    def get_mask_cmds(self):
        raise NotImplementedError

    def set_transmit_settings(self, transmit_mode, pkts_per_burst, pps):
        self.transmit_settings['transmit_mode'] = transmit_mode
        self.transmit_settings['pkts_per_burst'] = pkts_per_burst
        self.transmit_settings['pps'] = pps

class PG_flow_acd_request(PG_flow_t):
    def __init__(self, name, mac_src, ip_dst, vlan_tag=0):
        super(PG_flow_acd_request, self).__init__('arp', name)
        cmds = []
        pkt_len = 0

        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len += 2

        #L2 settings
        cmds.extend([
            'L2-src-addr {}'.format(mac_src),
            'L2-dest-addr 0000.0000.0000'
        ])
        pkt_len += 12

        #L3 settings
        cmds.extend([
            'L3-sender-haddr {}'.format(mac_src),
            'L3-target-haddr 0000.0000.0000',
            'L3-sender-paddr 0.0.0.0',
            'L3-target-paddr {}'.format(ip_dst)
        ])
        pkt_len += 20

        self.__config = cmds
        self.__pkt_len = pkt_len

    def get_config(self):
        return self.__config

class PG_flow_arp_request(PG_flow_t):
    def __init__(self, name, smac, sip, dip, vlan_tag=0):
        super(PG_flow_arp_request, self).__init__('arp', name)
        cmds = [
        ]

        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format('FFFF.FFFF.FFFF'),
            'L3-sender-haddr {}'.format(smac),
            'L3-sender-paddr {}'.format(sip),
        ])

        # Check if it is GARP
        if sip == dip:
            cmds.extend([
                'L3-target-haddr {}'.format('0000.0000.0000'),
                'L3-operation 2'
            ])
        else:
            cmds.extend([
                'L3-target-haddr {}'.format('FFFF.FFFF.FFFF'),
            ])
        pkt_len = pkt_len + 32

        cmds.extend([
            'L3-target-paddr {}'.format(dip),
            'data-length 18'
        ])
        pkt_len = pkt_len + 18

        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]
        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config

class PG_flow_dhcpv6(PG_flow_t):
    '''Class to create a dhcpv6 request/reply flow object for pagent
      Args:
        name ('str'): dhcpv6_req/dhcpv6_rep for a request/reply flow object
        src_mac ('str'): source mac address
        cid ('str', optional): client id, default None
        sid ('str', optional): server id, default None
        xid ('int', optional): transaction id, default 0
        requested_ip ('str', optional): requested ip address, default None
        src_ip ('str', optional): source ip address
        assigned_ip ('str', optional): assigned ip address, default None
        lease_time ('int', optional): ip address valid lifetime, default None
        vlan_tag ('int', optional): vlan identifier, default 0
      Usage:
        Set name to dhcpv6_req to configure a dhcpv6 request flow object and dhcpv6_rep for a reply flow object
    '''
    def __init__(self, name, src_mac, cid, sid, xid, requested_ip=None,
                 src_ip=None, assigned_ip=None, lease_time=None, vlan_tag=0):
        super(PG_flow_dhcpv6, self).__init__('template ,ethernet,ipv6,udp,dhcpv6', name)
        cmds = []

        include_prefix = True
        ALL_DHCPV6_SERVERS_MULTICAST = 'ff02::1:2'
        ALL_IPV6_NODES_MULTICAST = 'ff02::1'
        DHCP_MESSAGE_TYPE = None

        udp_header_code = pad_hex_num(0x11, 4, include_prefix)
        udp_src_port = pad_hex_num(0x0222, 4, include_prefix)
        udp_dst_port = pad_hex_num(0x0223, 4, include_prefix)

        if vlan_tag!=0:
            #L2 vlan settings
            cmds.extend([
                f'ethernet.vlan_id  {vlan_tag}',
                'ethernet.type 0x8100',
                'ethernet.vlan_tpid 0x8100'
            ])
        ipv6_src_int = None
        ipv6_dst_int = None
        l2_dst_addr = None

        if 'dhcpv6_req' in name:
            ipv6_src_int = convert_ip_to_int(make_link_local_ipv6(src_mac))
            ipv6_dst_int = convert_ip_to_int(ALL_DHCPV6_SERVERS_MULTICAST)
            DHCP_MESSAGE_TYPE = pad_hex_num(0x03, 4, include_prefix)
            l2_dst_addr = make_multicast_mac(ALL_DHCPV6_SERVERS_MULTICAST)
        else:
            ipv6_src_int = convert_ip_to_int(src_ip)
            ipv6_dst_int = convert_ip_to_int(ALL_IPV6_NODES_MULTICAST)
            DHCP_MESSAGE_TYPE = pad_hex_num(0x07, 4, include_prefix)
            l2_dst_addr = make_multicast_mac(ALL_IPV6_NODES_MULTICAST)

        #L2 settings
        cmds.extend([
            f'ethernet.src_addr {src_mac}',
            f'ethernet.dst_addr {l2_dst_addr}',
        ])
        #L3 settings
        cmds.extend([
            'ipv6.header.version 6',
            f'ipv6.header.next_header {udp_header_code}',
            f'ipv6.header.src_addr hex {ipv6_src_int:x}', #remove 0x prefix
            f'ipv6.header.dst_addr hex {ipv6_dst_int:x}' ##remove 0x prefix
        ])
        #L4 settings
        cmds.extend([
            f'udp.src {udp_src_port}',
            f'udp.dst {udp_dst_port}'
        ])

        #DHCP Settings
        cmds.extend([
            f'dhcpv6.message_type {DHCP_MESSAGE_TYPE}',
            f'dhcpv6.transaction_id[0] {pad_hex_num(xid, 6)}' #Ensures 3 byte xid
        ])

        options = PG_flow_dhcpv6_options_builder()
        if 'dhcpv6_req' in name:
            opts_arr = options \
            .build_dhcpv6_request_options(cid, sid, xid, requested_ip) \
            .build() \
            .convert_opts_to_arr()
            cmds.extend(opts_arr)
        else:
            opts_arr = options \
            .build_dhcpv6_reply_options(cid, sid, xid, assigned_ip, lease_time) \
            .build() \
            .convert_opts_to_arr()
            cmds.extend(opts_arr)

        self.__config = cmds

    def get_config(self):
        return self.__config

class PG_flow_igmp(PG_flow_t):
    def __init__(self, name, smac, sip, dip,
                 type_code, max_resp, grpip, vlan_tag=0):
        super(PG_flow_igmp, self).__init__('igmp', name)
        cmds = [
        ]
        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        map_addr = int(ipaddress.ip_address(dip))
        map_addr = map_addr & 0x7FFFFF
        dmac = '0100.5E%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
        ])

        pkt_len = pkt_len + 14 + 20

        type_code = type_code & 0xff
        cmds.extend([
            'L4-version {}'.format(type_code >> 4),
            'L4-type {}'.format(type_code & 0xf),
            'L4-max-resp {}'.format(max_resp),
            'L4-group-address {}'.format(grpip),
            'data-length 0',
        ])
        pkt_len = pkt_len + 8

        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match add igmp',
            'match 3 start-at packet-start offset 0 length {}'.format(pkt_len),
        ]
        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config


class PG_flow_igmp_query(PG_flow_igmp):
    def __init__(self, name, smac, sip, max_resp, vlan_tag=0):
        super(PG_flow_igmp_query, self).__init__(name, smac, sip,
                                                 igmp_query_dstip,
                                                 0x11, max_resp,
                                                 '0.0.0.0', vlan_tag)


class PG_flow_igmp_leave(PG_flow_igmp):
    def __init__(self, name, smac, sip, grpip, vlan_tag=0):
        super(PG_flow_igmp_leave, self).__init__(name, smac, sip,
                                                 igmp_leave_dstip, 0x17, 0,
                                                 grpip, vlan_tag)


class PG_flow_igmpv1_report(PG_flow_igmp):
    def __init__(self, name, smac, sip, grpip, vlan_tag=0):
        super(PG_flow_igmpv1_report, self).__init__(name, smac, sip,
                                                    grpip, 0x12, 0,
                                                    grpip, vlan_tag)


class PG_flow_igmpv2_report(PG_flow_igmp):
    def __init__(self, name, smac, sip, grpip, vlan_tag=0):
        super(PG_flow_igmpv2_report, self).__init__(name, smac, sip,
                                                    grpip, 0x16, 0,
                                                    grpip, vlan_tag)


class PG_flow_igmpv3_report(PG_flow_t):
    def __init__(self, name, smac, sip, grpip,
                 src_num, src_list, mode_code, vlan_tag=0):
        super(PG_flow_igmpv3_report, self).__init__('igmp', name)

        type_code = 0x22
        cmds = [
        ]
        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        map_addr = int(ipaddress.ip_address(igmpv3_report_dstip))
        map_addr = map_addr & 0x7FFFFF
        dmac = '0100.5E%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(igmpv3_report_dstip),
        ])

        pkt_len = pkt_len + 14 + 20

        type_code = type_code & 0xff
        cmds.extend([
            'L4-version {}'.format(type_code >> 4),
            'L4-type {}'.format(type_code & 0xf),
            'L4-max-resp 0',
            'L4-group-address 0.0.0.1',  # Hack IGMPv1 to match IGMPv3 format
        ])
        pkt_len = pkt_len + 8
        data_len = 0
        data = ''
        record_hdr = 0
        record_hdr = '%02X00%04X' % (mode_code, src_num)
        data = data + record_hdr
        data_len = data_len + 4
        grpip_value = int(ipaddress.ip_address(grpip))
        grpip_hex = '%08X' % grpip_value
        data = data + grpip_hex
        data_len = data_len + 4
        for src in src_list:
            srcip_value = int(ipaddress.ip_address(src))
            srcip_hex = '%08X' % srcip_value
            data = data + srcip_hex
            data_len = data_len + 4

        cmds.extend([
            'data-length {}'.format(data_len),
            'data 0 {}'.format(data),
        ])

        pkt_len = pkt_len + data_len
        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match add igmp',
            'match 3 start-at packet-start offset 0 length {}'.format(pkt_len),
        ]
        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config


class PG_flow_igmpv3_query(PG_flow_t):
    def __init__(self, name, smac, sip, max_resp, grpip,
                 src_num, src_list, vlan_tag=0):
        super(PG_flow_igmpv3_query, self).__init__('igmp', name)

        type_code = 0x11
        cmds = [
        ]
        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        map_addr = int(ipaddress.ip_address(igmp_query_dstip))
        map_addr = map_addr & 0x7FFFFF
        dmac = '0100.5E%02X.%04X' % (map_addr >> 16, map_addr & 0xFFFF)
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(igmp_query_dstip),
        ])

        pkt_len = pkt_len + 14 + 20

        type_code = type_code & 0xff
        cmds.extend([
            'L4-version {}'.format(type_code >> 4),
            'L4-type {}'.format(type_code & 0xf),
            'L4-max-resp {}'.format(max_resp),
            'L4-group-address {}'.format(grpip)
        ])
        pkt_len = pkt_len + 8
        data_len = 0
        data = ''
        record_hdr = 0
        record_hdr = '0000%04X' % src_num
        data = data + record_hdr
        data_len = data_len + 4

        for src in src_list:
            srcip_value = int(ipaddress.ip_address(src))
            srcip_hex = '%08X' % srcip_value
            data = data + srcip_hex
            data_len = data_len + 4

        cmds.extend([
            'data-length {}'.format(data_len),
            'data 0 {}'.format(data),
        ])

        pkt_len = pkt_len + data_len
        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]
        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config


class PG_flow_rawip(PG_flow_t):
    '''Class to create a raw ipv4 object for pagent
      Args:
        name ('str'): raw ipv4 flow object
        smac ('str'): source mac address
        dmac ('str'): destination mac address
        sip ('str'): source ipv4
        dip ('str'): destination ipv4
        vlan_tag ('int', optional): vlan tag, default 0
        data_length ('str', optional): l3 data length
        kwargs ('dict', optional): other flow variables
      Usage:
        Configure a raw ipv4 flow object
    '''
    def __init__(self, name, smac, dmac,
                 sip, dip, vlan_tag=0, data_length=18, **kwargs):
        super(PG_flow_rawip, self).__init__('ip', name)
        cmds = [
        ]

        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
        ])

        if 'ttl' in kwargs:
            cmds.extend([
                'L3-ttl {}'.format(kwargs['ttl']),
            ])

        cmds.extend([
            'data-length {}'.format(data_length)
        ])
        pkt_len = pkt_len + 14 + 20 + data_length

        self.__config = cmds
        self.__pkt_len = pkt_len

        for key, value in kwargs.items():
            key = key.replace('_','-')
            cmds.extend([
                '{} {}'.format(key, value)
            ])

        mask_cmds = [
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]
        if 'ttl' not in kwargs:
            mask_cmds.extend([
                'match mask-start L3-ttl offset 0 length 4',
                'match mask-data 0 00FF0000'
            ])
        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config

class PG_flow_rawipv6(PG_flow_t):
    '''Class to create a raw ipv6 object for pagent
      Args:
        name ('str'): raw ipv6 flow object
        smac ('str'): source mac address
        dmac ('str'): destination mac address
        sip ('str'): source ipv6
        dip ('str'): destination ipv6
        vlan_tag ('int', optional): vlan tag, default 0
        data_length ('str', optional): l3 data length
        kwargs ('dict', optional): other flow variables
      Usage:
        Configure a raw ipv6 flow object
    '''
    def __init__(self, name, smac, dmac,
                 sip, dip, vlan_tag=0, data_length=18, **kwargs):
        super(PG_flow_rawipv6, self).__init__('ipv6', name)
        cmds = [
        ]

        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
        ])

        if 'ttl' in kwargs:
            cmds.extend([
                'L3-hop-limit {}'.format(kwargs['ttl']),
            ])

        cmds.extend([
            'data-length {}'.format(data_length)
        ])
        pkt_len = pkt_len + 14 + 40 + data_length

        self.__config = cmds
        self.__pkt_len = pkt_len

        for key, value in kwargs.items():
            key = key.replace('_','-')
            cmds.extend([
                '{} {}'.format(key, value)
            ])

        mask_cmds = [
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]
        if 'ttl' not in kwargs:
            mask_cmds.extend([
                'match mask-start L3-hop-limit offset 0 length 1',
                'match mask-data 0 00'
            ])
        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config

class PG_flow_ndp_ns(PG_flow_t):
    def __init__(self, name, smac, sip, dip, vlan_tag=0, **kwargs):
        super(PG_flow_ndp_ns, self).__init__('icmpv6', name)
        cmds = [
        ]

        length_mode = kwargs.get('length_mode', 'auto')
        cmds.extend([
            'length {length_mode}'.format(length_mode=length_mode),
        ])

        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        l3target_full = ipaddress.IPv6Address(dip).exploded
        low24 = l3target_full[32:]
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr 3333.ff{}.{}'.format(low24[0:2], low24[3:]),
        ])

        limit = kwargs.get('hop_limit', 255)
        cmds.extend([
            'L3-traffic-class 224',
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr ff02::1:ff{}:{}'.format(low24[0:2], low24[3:]),
            'L3-hop-limit {limit}'.format(limit=limit),
        ])

        pkt_len = pkt_len + 40

        # DAD Packet
        if sip == "::":
            cmds.extend([
                'L4-message 0 00000000{}'.format(l3target_full.replace(':', ' ')),
            ])
            pkt_len = pkt_len + 4 + 16
        else:
            cmds.extend([
                'data 0 00000000{}0101{}'.format(l3target_full.replace(':', ''),
                                                 smac.replace('.', ''))
            ])
            pkt_len = pkt_len + 4 + 16 + 8

        cmds.extend([
            'L4-type 135',
            'L4-code 0',
        ])

        # Type is 1 byte, code is 1 byte, checksum is 2 bytes (autofilled)
        pkt_len = pkt_len + 4

        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]

        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config


class PG_flow_ndp_na(PG_flow_t):
    def __init__(self, name, smac, dmac, sip, dip, vlan_tag=0, **kwargs):
        super(PG_flow_ndp_na, self).__init__('icmpv6', name)
        cmds = [
        ]

        length_mode = kwargs.get('length_mode', 'auto')
        cmds.extend([
            'length {length_mode}'.format(length_mode=length_mode),
        ])

        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len + 2

        # flag is solicited + override
        flag = 6
        if 'FF02::1' == dip or 'ff02::1' == dip:
            l3target_full = ipaddress.IPv6Address(dip).exploded
            low24 = l3target_full[32:]
            dmac = '3333.ff{}.{}'.format(low24[0:2], low24[3:])
            # flag is unsolicited + override
            flag = 1

        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
        ])

        limit = kwargs.get('hop_limit', 255)
        cmds.extend([
            'L3-traffic-class 224',
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
            'L3-hop-limit {limit}'.format(limit=limit),
        ])

        pkt_len = pkt_len + 40

        l3target_full = ipaddress.IPv6Address(sip).exploded
        cmds.extend([
            'L4-type 136',
            'L4-code 0',
            'data 0 {}0000000{}0201{}'.format(flag,
                                              l3target_full.replace(':', ''),
                                              smac.replace('.', ''))
        ])

        pkt_len = pkt_len + 8 + 16 + 8

        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]

        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config
class PG_flow_dhcp_options():
    '''Args:
         builder: dhcpv4/dhcpv6 builder object
      NOTE: This class should only be instantiated from a builder class by calling the build method
    '''
    def __init__(self, builder):
        self.dhcp_options = builder.dhcp_options
        self.dhcp_version = builder.dhcp_version

    def convert_opts_to_arr(self):
        '''Converts options dictonary to an array'''
        res = []
        version = self.dhcp_version

        for index, opt in enumerate(self.dhcp_options):
            for key, val in self.dhcp_options[opt].items():
                if key == 'data':
                    res.append(f'dhcpv{version}.options[{index}].{key}[0] {val}')
                else:
                    res.append(f'dhcpv{version}.options[{index}].{key} {val}')
        return res

class PG_flow_dhcpv6_options_builder():
    '''Builds dhcpv6 request/reply options
      Usage:
        Dhcpv6 request/reply object with default options can be build the following way:
          Request
            PG_flow_dhcpv6_options_builder()
            .build_dhcpv6_request_options(cid, sid, xid, requested_ip)
            .build()
          Reply
            PG_flow_dhcpv6_options_builder()
            .build_dhcpv6_reply_options(cid, sid, xid, assigned_ip, lease_time)
            .build()
        add_options(options) can be used to add additional options to dhcpv6 request/reply
    '''
    def __init__(self):
        self.dhcp_options = {}
        self.dhcp_version = 6

    def add_options(self, options):
        '''Args:
            options - dictonary containing code, length, data padded. See RFC standard
            Usage:
            options = {
                code : hex,
                length: hex,
                data: hex
            }
            PG_flow_dhcpv6_options_builder().add_options(options)
        '''
        self.dhcp_options.update(options)
        return self

    def build(self):
        '''Builds dhcp_options object'''
        return PG_flow_dhcp_options(self)

    def _add_common_options(self, cid, sid):
        OPTION_CLIENTID = pad_hex_num(0x0001, 4, True)
        OPTION_SERVERID = pad_hex_num(0x0002, 4, True)

        OPTION_ORO = pad_hex_num(0x0006, 4, True)
        #Option ORO data
        OPTION_DNS_SERVERS = pad_hex_num(0x0017, 4)
        OPTION_DOMAIN_LIST = pad_hex_num(0x0018, 4)

        self.dhcp_options['opt_request'] = {
                'code': OPTION_ORO, #DHCPv6 option code
                'length': pad_hex_num(0x0004, 4, True), #Length in bytes from RFC
                'data': f'{OPTION_DNS_SERVERS}{OPTION_DOMAIN_LIST}'
            }
        if cid:
            self.dhcp_options['client_id'] = {
                'code': OPTION_CLIENTID,
                'length': pad_hex_num(0x000E, 4, True), #Length in bytes from RFC
                'data': pad_hex_num(cid, 28) #Ensures 14 byte cid
            }
        if sid:
            self.dhcp_options['server_id'] = {
                'code': OPTION_SERVERID,
                'length': pad_hex_num(0x000E, 4, True),
                'data': pad_hex_num(sid, 28) #Ensures 14 byte sid
            }

    def build_dhcpv6_request_options(self, cid, sid, xid, requested_ip):
        '''Args:
             cid ('str'): dhcpv6 client id
             sid ('str'): dhcpv6 server id
             xid ('int'): dhcpv6 transaction id
             requested_ip('str'): dhcpv6 client requested ip
        '''
        requested_ip_int = convert_ip_to_int(requested_ip)

        OPTION_IA_NA = pad_hex_num(0x0003, 4, True)
        #IA Address Address sub option
        OPTION_IAADDR = pad_hex_num(0x0005, 4)
        IA_ID = pad_hex_num(xid, 8)
        T1_INFINITE = pad_hex_num(0xffffffff, 8)
        T2_INFINITE = pad_hex_num(0xffffffff, 8)

        self._add_common_options(cid, sid)
        #Suboptions are encoded within the datafield of the parent option
        self.dhcp_options['iana'] = {
                'code': OPTION_IA_NA,
                'length': pad_hex_num(0x0028, 4, True), #Length in bytes from RFC
                'data': (
                    f'{IA_ID}{T1_INFINITE}{T2_INFINITE}'
                    f'{OPTION_IAADDR}{pad_hex_num(0x0018, 4)}'
                    f'{requested_ip_int:x}{T1_INFINITE}{T2_INFINITE}'
                )
            }
        return self

    def build_dhcpv6_reply_options(self, cid, sid, xid, assigned_ip, lease_time):
        '''Args:
             cid ('str'): dhcpv6 client
             sid ('str'): dhcpv6 server id
             xid ('int'): dhcpv6 transaction id
             assigned_ip ('str'): dhcpv6 ip assigned to the client
             lease_time ('int'): valid lifetime of assigned ipv6 address
        '''
        self._add_common_options(cid, sid)
        assigned_ip_int = convert_ip_to_int(assigned_ip)
        OPTION_IA_NA = pad_hex_num(0x0003, 4, True)
        #IA Address Address sub option
        OPTION_IAADDR = pad_hex_num(0x0005, 4)

        IA_ID = pad_hex_num(xid, 8)
        T1_INFINITE = pad_hex_num(0xffffffff, 8)
        T2_INFINITE = pad_hex_num(0xffffffff, 8)
        IA_ADDR_VALID_LIFETIME = pad_hex_num(lease_time, 8)

        self.dhcp_options['iana'] = {
                'code': OPTION_IA_NA,
                'length': pad_hex_num(0x0028, 4, True), #Length in bytes from RFC
                'data': (
                    f'{IA_ID}{T1_INFINITE}{T2_INFINITE}'
                    f'{OPTION_IAADDR}{pad_hex_num(0x0018, 4)}'
                    f'{assigned_ip_int:x}{IA_ADDR_VALID_LIFETIME}{IA_ADDR_VALID_LIFETIME}'
                )
            }

        return self
class PG_flow_dhcpv4_options_builder():
    '''Builds dhcpv4 request/reply options
      Usage:
        Dhcpv4 request/reply with default options object can be build the following way:
          Request
            PG_flow_dhcpv4_options_builder()
            .build_dhcpv4_request_options(requested_ip)
            .build()
          Reply
            PG_flow_dhcpv6_options_builder()
            .build_dhcpv6_reply_options(lease_time)
            .build()
        add_options(options) can be used to add additional options to dhcpv6 request/reply
    '''
    def __init__(self):
        self.dhcp_options = {}
        self.dhcp_version = 4

    def _add_option_end(self):
        DHCP_OPTION_END = 255
        self.dhcp_options['end'] = {
            'code': DHCP_OPTION_END,
            'length': 0x01,
            'data': 'FF',
        }

    def add_options(self, options):
        '''Args:
             options - dictonary containing code, length, data padded. See RFC standard
          Usage:
            options = {
              code : hex,
              length: hex,
              data: hex
            }
            PG_flow_dhcpv6_options_builder().add_options(options)
        '''
        self.dhcp_options.update(options)
        return self

    def build(self):
        '''Builds dhcp_options object'''
        self._add_option_end()
        return PG_flow_dhcp_options(self)

    def build_dhcpv4_request_options(self, requested_ip):
        '''Args:
             requested_ip('str'): dhcpv6 client requested ip
        '''
        DHCP_MESSAGE_TYPE_CODE = 0x35
        DHCP_REQUEST_CODE = 0x32
        DHCP_REQUEST_MESSAGE_TYPE = 3

        requested_ip_encoded = int(ipaddress.IPv4Address(requested_ip))

        self.dhcp_options['msg_type'] = {
            'code': DHCP_MESSAGE_TYPE_CODE,
            'length': 0x01,
            'data': DHCP_REQUEST_MESSAGE_TYPE,
        }
        self.dhcp_options['request_code'] = {
            'code': DHCP_REQUEST_CODE,
            'length': 0x04,
            'data': f'{requested_ip_encoded:x}',
        }

        return self

    def build_dhcpv4_reply_options(self, lease_time):
        '''Args:
             lease_time('int'): dhcpv6 client assigned ip
        '''
        DHCP_MESSAGE_TYPE_CODE = 0x35
        DHCP_LEASE_CODE = 0x33
        DHCP_REPLY_MESSAGE_TYPE = 5

        self.dhcp_options['msg_type'] = {
            'code': DHCP_MESSAGE_TYPE_CODE,
            'length': 0x01,
            'data': DHCP_REPLY_MESSAGE_TYPE,
        }
        self.dhcp_options['lease'] = {
            'code': DHCP_LEASE_CODE,
            'length': 0x04,
            'data': f'{lease_time:x}',
        }

        return self
class PG_flow_dhcpv4(PG_flow_t):
    '''Class to create a dhcpv4 request/reply flow object for pagent
      Args:
        name ('str'): dhcpv4_request/dhcpv4_reply for a request/reply flow object
        mac_src ('str'): source mac address
        xid ('int', optional): transaction id, default 0
        requested_ip ('str', optional): requested ip address, default 0.0.0.0
        ip_src ('str', optional): source ip address, default 0.0.0.0
        assigned_ip ('str', optional): assigned ip address, default 0.0.0.0
        lease_time ('int', optional): ip address valid lifetime, default 0
      Usage:
        Set name to dhcpv4_request to configure a dhcpv4 request flow object and dhcpv4_reply for a reply flow object
    '''
    def __init__(self, name, mac_src, xid, **kwargs):
        super(PG_flow_dhcpv4, self).__init__('template ,ethernet,ip,udp,dhcpv4', name)
        cmds = []

        #L2 settings
        cmds.extend([
            f'ethernet.src_addr {mac_src}',
            'ethernet.dst_addr FFFF.FFFF.FFFF',
        ])

        #L3 settings
        ip_src = kwargs.get('ip_src', '0.0.0.0')
        cmds.extend([
            f'ip.src_addr {ip_src}',
            'ip.dst_addr 255.255.255.255',
        ])

        #L4 settings
        cmds.extend([
            f'dhcpv4.xid {xid}',
        ])

        options = PG_flow_dhcpv4_options_builder()

        if name == 'dhcpv4_request':
            requested_ip = kwargs.get('requested_ip', '0.0.0.0')
            opts_arr = options.build_dhcpv4_request_options(requested_ip) \
                       .build() \
                       .convert_opts_to_arr()

            cmds.extend([
                'dhcpv4.op 0x01', # request code
            ])
            cmds.extend(opts_arr)
        elif name == "dhcpv4_reply":
            assigned_ip = kwargs.get('assigned_ip', '0.0.0.0')
            lease_time = kwargs.get('lease_time', 0)
            opts_arr = options.build_dhcpv4_reply_options(lease_time) \
                       .build() \
                       .convert_opts_to_arr()

            cmds.extend([
                'dhcpv4.op 0x02', # reply code
                f'dhcpv4.yiaddr {assigned_ip}',
                f'dhcpv4.siaddr {ip_src}',
            ])
            cmds.extend(opts_arr)

        self.__config = cmds

    def get_config(self):
        return self.__config

class PG_flow_mldv1(PG_flow_t):
    def __init__(self, name, smac, sip, dip,
                  type_code, max_resp, grpip, vlan_tag=0):
        super(PG_flow_mldv1, self).__init__('icmpv6', name)
        cmds = [
        ]
        pkt_len = 0
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len+4

        map_addr = int(ipaddress.IPv6Address(dip))
        map_addr = map_addr & 0xFFFFFFFF
        dmac = '3333.%04X.%04X' %(map_addr >> 16, map_addr & 0xFFFF)
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
        ])

        pkt_len = pkt_len+14+40

        cmds.extend([
            'L3-hop-limit 1',
            'L3-next-header 0',
            'L3-header total 1 modules',
            'L3-header 0 is hop_by_hop',
            'L3-header 0 next-header 58',
            'L3-header 0 option 0 0 0502',
        ])

        pkt_len = pkt_len+8

        cmds.extend([
            'L4-type {}'.format(type_code),
        ])

        data = ''
        data_len = 0
        max_resp_hex = '%04X' % max_resp
        data += max_resp_hex
        grpip_value = int(ipaddress.IPv6Address(grpip))
        grpip_hex = '0000%032X' % grpip_value
        data += grpip_hex
        data_len += 24

        cmds.extend([
            'L4-message 0 {}'.format(data),
        ])

        pkt_len = pkt_len+data_len

        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match add icmpv6',
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]

        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config

class PG_flow_mldv1_query(PG_flow_mldv1):
    def __init__(self, name, smac, sip, dip, max_resp, grpip, vlan_tag=0):
        super(PG_flow_mldv1_query, self).__init__(name, smac, sip,
                    dip, 130, max_resp, grpip, vlan_tag)

class PG_flow_mldv1_report(PG_flow_mldv1):
    def __init__(self, name, smac, sip, dip, grpip, vlan_tag=0):
        super(PG_flow_mldv1_report, self).__init__(name, smac, sip,
                    dip, 131, 0, grpip, vlan_tag)

class PG_flow_mldv1_done(PG_flow_mldv1):
    def __init__(self, name, smac, sip, grpip, vlan_tag=0):
        super(PG_flow_mldv1_done, self).__init__(name, smac, sip,
                    'FF02::2', 132, 0, grpip, vlan_tag)

class PG_flow_mldv2_query(PG_flow_t):
    def __init__(self, name, smac, sip, dip, max_resp,
                 grpip, qqic, src_num, src_list, vlan_tag=0, qrv=2):
        super(PG_flow_mldv2_query, self).__init__('icmpv6', name)
        cmds = [
        ]
        pkt_len = 0

        type_code = 130
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len+4

        map_addr = int(ipaddress.IPv6Address(dip))
        map_addr = map_addr & 0xFFFFFFFF
        dmac = '3333.%04X.%04X' %(map_addr >> 16, map_addr & 0xFFFF)
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
        ])

        pkt_len = pkt_len+14+40

        cmds.extend([
            'L3-hop-limit 1',
            'L3-next-header 0',
            'L3-header total 1 modules',
            'L3-header 0 is hop_by_hop',
            'L3-header 0 next-header 58',
            'L3-header 0 option 0 0 0502',
        ])

        pkt_len = pkt_len+8

        cmds.extend([
            'L4-type {}'.format(type_code),
        ])

        data = ''
        data_len = 0
        max_resp_hex = '%04X' % max_resp
        data += max_resp_hex
        grpip_value = int(ipaddress.IPv6Address(grpip))
        grpip_hex = '0000%032X' % grpip_value
        data += grpip_hex
        qrv_hex = '%02X' % qrv
        data += qrv_hex
        qqic_hex = '%02X' % qqic
        data += qqic_hex
        src_num_hex = '%04X' % src_num
        data += src_num_hex
        data_len += 28

        for src in range(src_num):
            srcip_value = int(ipaddress.IPv6Address(src_list[src]))
            srcip_hex = '%032X' % srcip_value
            data += srcip_hex
            data_len += 16

        cmds.extend([
            'L4-message 0 {}'.format(data),
        ])

        pkt_len = pkt_len+data_len

        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match add icmpv6',
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]

        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config


class PG_flow_mldv2_report(PG_flow_t):
    def __init__(self, name, smac, sip, grpip, src_num, src_list,
                 mode_code, vlan_tag=0):
        super(PG_flow_mldv2_report, self).__init__('icmpv6', name)
        cmds = [
        ]
        pkt_len = 0

        type_code = 143
        dip = 'FF02::16'
        if 0 != vlan_tag:
            cmds.extend([
                'layer 2 ethernet',
                'l2-shim is dot1q',
                'l2-shim vlan-id {}'.format(vlan_tag),
            ])
            pkt_len = pkt_len+4

        map_addr = int(ipaddress.IPv6Address(dip))
        map_addr = map_addr & 0xFFFFFFFF
        dmac = '3333.%04X.%04X' %(map_addr >> 16, map_addr & 0xFFFF)
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
        ])

        pkt_len = pkt_len+14+40

        cmds.extend([
            'L3-hop-limit 1',
            'L3-next-header 0',
            'L3-header total 1 modules',
            'L3-header 0 is hop_by_hop',
            'L3-header 0 next-header 58',
            'L3-header 0 option 0 0 0502',
        ])

        pkt_len = pkt_len+8

        cmds.extend([
            'L4-type {}'.format(type_code),
        ])

        data = ''
        data_len = 0
        record_num = 1
        record_num_hex = '0000%04X' % record_num
        data += record_num_hex
        record_hdr_hex = '%02X00%04X' %(mode_code,src_num)
        data += record_hdr_hex
        grpip_value = int(ipaddress.IPv6Address(grpip))
        grpip_hex = '%032X' % grpip_value
        data += grpip_hex
        data_len +=28

        for src in range(src_num):
            srcip_value = int(ipaddress.IPv6Address(src_list[src]))
            srcip_hex = '%032X' % srcip_value
            data += srcip_hex
            data_len += 16

        cmds.extend([
            'L4-message 0 {}'.format(data),
        ])

        pkt_len = pkt_len+data_len
        self.__config = cmds
        self.__pkt_len = pkt_len

        mask_cmds = [
            'match add icmpv6',
            'match start-at packet-start offset 0 length {}'.format(pkt_len),
        ]

        self.__mask_cmds = mask_cmds

    def get_mask_cmds(self):
        return self.__mask_cmds

    def get_config(self):
        return self.__config

class PG_Manager(object):
    def __init__(self, device):
        self.__tg = device
        self.__intfs = []

    def get_tg(self):
        return self.__tg

    def _get_short_ifname_by_name(self, ifname):
        short = ifname
        if ifname.startswith('Ethernet'):
            short = ifname.replace('Ethernet', 'Et')
        return short

    def __addintf(self, intf):
        if intf not in self.__intfs:
            self.__intfs.append(intf)

    def start_traffic(self, port, flows, wait_time=1):
        for flow in flows:
            self.send_traffic(flow, port)
            time.sleep(wait_time)

    def stop_traffic(self, port, stop_only=False):
        self.__tg.execute('tgn {}'.format(port))
        if not stop_only:
            self.__tg.execute('tgn delete traffic-stream from 1')
        self.__tg.execute('tgn stop')

    def configure_traffic(self, port, flow, clear=False):
        '''Configure traffic according to flow variables
           Args:
             port ('str'): interface to be configured traffic
             flow ('object'): PG_flow object
             clear ('bool', Optional): clear the all traffics before configure
            Return:
              None
        '''
        if clear:
            self.__tg.execute('tgn clear all')

        self.__tg.execute('tgn ' + port)
        self.__tg.execute('tgn add {}'.format(flow.get_template()))
        self.__tg.execute('tgn name {}'.format(flow.get_name()))
        for cmd in flow.get_config():
            self.__tg.execute('tgn ' + cmd)

        self.__tg.execute('tgn on')

        transmit_mode = flow.transmit_settings['transmit_mode']
        pkts_per_burst = flow.transmit_settings['pkts_per_burst']
        pps = flow.transmit_settings['pps']

        if (self.is_traffic_configured(flow)):
            if transmit_mode == 'single_burst':
                self.__tg.execute('tgn send {}'.format(pkts_per_burst))
            elif transmit_mode == 'continuous':
                self.__tg.execute('tgn burst off')
                self.__tg.execute('tgn rate {}'.format(pps))
            else:
                burst_duration_ms = int((pkts_per_burst/pps)*1000)
                self.__tg.execute('tgn burst on')
                self.__tg.execute('tgn burst duration on {}'.format(burst_duration_ms))
        else:
            self.__tg.execute('tgn rate {}'.format(pps))
            self.__tg.execute('tgn send {}'.format(pkts_per_burst))

        # Clean the buffer to remove any remaining device prompt
        self.__tg.spawn.read_update_buffer()
        self.__tg.spawn.buffer = ''

    def is_traffic_configured(self, flow):
        transmit_mode = flow.transmit_settings['transmit_mode']
        if transmit_mode:
            return True
        else:
             return False

    def send_configured_traffic(self, flow):
        transmit_mode = flow.transmit_settings['transmit_mode']
        pkts_per_burst = flow.transmit_settings['pkts_per_burst']
        pps = flow.transmit_settings['pps']

        if transmit_mode == 'single_burst':
            self.__tg.execute('tgn send {}'.format(pkts_per_burst))
            self.__tg.execute('tgn start send')
        elif transmit_mode == 'continuous':
            self.__tg.execute('tgn burst off')
            self.__tg.execute('tgn rate {}'.format(pps))
            self.__tg.execute('tgn start')
        else:
            burst_duration_ms = int((pkts_per_burst/pps)*1000)
            self.__tg.execute('tgn burst on')
            self.__tg.execute('tgn burst duration on {}'.format(burst_duration_ms))
            self.__tg.execute('tgn start')

    def send_traffic(self, flow, send_intf, pps=1, repeat=1):
        self.__addintf(send_intf)
        '''need modification'''
        cfg = [
            f"interface {send_intf}",
            "no shutdown",
        ]

        self.__tg.configure(cfg)
        self.__tg.execute('tgn clear all')
        self.__tg.execute('tgn ' + send_intf)
        self.__tg.execute('tgn add {}'.format(flow.get_template()))
        self.__tg.execute('tgn name {}'.format(flow.get_name()))
        for cmd in flow.get_config():
            self.__tg.execute('tgn ' + cmd)

        self.__tg.execute('tgn on')

        if (self.is_traffic_configured(flow)):
            self.send_configured_traffic(flow)
        else:
            self.__tg.execute('tgn rate {}'.format(pps))
            self.__tg.execute('tgn send {}'.format(repeat))
            self.__tg.sendline('tgn start send')
            '''find replacement'''
            self.__tg.expect('   Send process complete.', timeout=1000)

        # Clean the buffer to remove any remaining device prompt
        self.__tg.spawn.read_update_buffer()
        self.__tg.spawn.buffer = ''

    def add_filter(self, filter_type, flow, intf):
        self.__addintf(intf)
        if_short_name = self._get_short_ifname_by_name(intf)
        self.__tg.execute('pkts filter ' + intf)
        self.__tg.execute(
            'pkts filter add {} {} in'.format(
                flow.get_template(), filter_type))
        self.__tg.execute('pkts filter name {}_{}'.format(if_short_name,
                                                          flow.get_name()))
        for cmd in flow.get_config():
            self.__tg.execute('pkts filter ' + cmd)
        for cmd in flow.get_mask_cmds():
            self.__tg.execute('pkts filter ' + cmd)
        self.__tg.execute('pkts filter active')

    def add_fastcount_filter(self, flow, intf):
        self.__addintf(intf)
        cfg = [
            f"interface {intf}",
            "no shutdown",
        ]
        self.__tg.configure(cfg)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {} fast-count on'.format(intf))
        self.add_filter('fast-count', flow, intf)

    def add_display_filter(self, flow, intf):
        self.__addintf(intf)
        cfg = [
            f"interface {intf}",
            "no shutdown",
        ]
        self.__tg.configure(cfg)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {} fast-count on'.format(intf))
        self.add_filter('display', flow, intf)

    def add_capture_filter(self, flow, intf):
        self.__addintf(intf)
        cfg = [
            f"interface {intf}",
            "no shutdown",
        ]
        self.__tg.configure(cfg)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {} fast-count on'.format(intf))
        self.add_filter('capture', flow, intf)

    def add_cap_buffer(self, intf):
        self.__addintf(intf)
        cfg = [
            f"interface {intf}",
            "no shutdown",
        ]
        self.__tg.configure(cfg)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {}'.format(intf))
        self.__tg.execute('pkts add 1000000')

    def start_pkts_count(self):
        self.__tg.execute('pkts start')

    def stop_pkts_count(self):
        self.__tg.execute('pkts stop')

    def load_template(self, template_file):
        self.clear_template()
        self.__tg.execute('template load unix:{}'.format(template_file))

    def clear_template(self):
        self.__tg.execute('template clear')

    def clear_tgn(self):
        self.__tg.execute('tgn clear all')

    def clear_pkts(self):
        self.__tg.execute('pkts clear all')
        self.__tg.execute('pkts filter clear filters')
        for intf in self.__intfs:
            self.__tg.execute('pkts {} promiscuous off'.format(intf))
            self.__tg.execute('pkts {} fast-count off'.format(intf))

    def clear_all(self):
        self.clear_tgn()
        self.clear_pkts()

    def get_fastcount(self, flow_name, intf):
        self.__addintf(intf)
        if_short_name = self._get_short_ifname_by_name(intf)
        filter_name = '{}_{}'.format(if_short_name, flow_name)
        output = self.__tg.execute('pkts show fast-count tcl-output')
        mo = re.search(r'{} incoming count (\d+)'.format(filter_name), output)
        if mo:
            return int(mo.group(1))
        else:
            return -1

    def get_capturecount(self, flow, intf):
        self.__addintf(intf)
        if_short_name = self._get_short_ifname_by_name(intf)
        filter_name = '{}_{}'.format(if_short_name, flow.get_name())
        output = self.__tg.execute('pkts show all')
        output = self.__tg.execute('pkts show capture-count tcl-output')
        mo = re.search(r'{} incoming count (\d+)'.format(filter_name), output)
        if mo:
            return int(mo.group(1))
        else:
            return -1
