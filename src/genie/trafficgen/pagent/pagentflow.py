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

    def get_template(self):
        return self.__template

    def get_name(self):
        return self.__flow_name

    def get_config(self):
        raise NotImplementedError

    def get_mask_cmds(self):
        raise NotImplementedError


class PG_flow_arp(PG_flow_t):
    def __init__(self, name, smac, dmac, sip, dip, vlan_tag=0):
        super(PG_flow_arp, self).__init__('arp', name)
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
            'L3-sender-haddr {}'.format(smac),
            'L3-sender-paddr {}'.format(sip),
        ])

        # Check if it is GARP
        if sip == dip:
            cmds.extend([
                'L3-target-haddr {}'.format('0000.0000.0000'),
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
    def __init__(self, name, smac, dmac, sip, dip, vlan_tag=0, **kwargs):
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
            'data-length 18'
        ])
        pkt_len = pkt_len + 14 + 20 + 18

        self.__config = cmds
        self.__pkt_len = pkt_len

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


class PG_flow_ndp_ns(PG_flow_t):
    def __init__(self, name, smac, sip, dip, vlan_tag=0, **kwargs):
        super(PG_flow_ndp_ns, self).__init__('icmpv6', name)
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

        l3target_full = ipaddress.IPv6Address(dip).exploded
        low24 = l3target_full[32:]
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr 3333.ff{}.{}'.format(low24[0:2], low24[3:]),
        ])

        cmds.extend([
            'L3-traffic-class 224',
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr ff02::1:ff{}:{}'.format(low24[0:2], low24[3:]),
            'L3-hop-limit 255',
        ])

        pkt_len = pkt_len + 40

        cmds.extend([
            'L4-type 135',
            'L4-code 0',
            'data 0 00000000{}0101{}'.format(l3target_full.replace(':', ''),
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


class PG_flow_ndp_na(PG_flow_t):
    def __init__(self, name, smac, dmac, sip, dip, vlan_tag=0, **kwargs):
        super(PG_flow_ndp_na, self).__init__('icmpv6', name)
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

        l3target_full = ipaddress.IPv6Address(sip).exploded
        cmds.extend([
            'L2-src-addr {}'.format(smac),
            'L2-dest-addr {}'.format(dmac),
        ])

        cmds.extend([
            'L3-traffic-class 224',
            'L3-src-addr {}'.format(sip),
            'L3-dest-addr {}'.format(dip),
            'L3-hop-limit 255',
        ])

        pkt_len = pkt_len + 40

        cmds.extend([
            'L4-type 136',
            'L4-code 0',
            'data 0 60000000{}0201{}'.format(l3target_full.replace(':', ''),
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


class PG_flow_rawipv6(PG_flow_t):
    def __init__(self, name, smac, dmac, sip, dip, vlan_tag=0, **kwargs):
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
            'data-length 18'
        ])
        pkt_len = pkt_len + 14 + 40 + 18

        self.__config = cmds
        self.__pkt_len = pkt_len

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

    def send_traffic(self, flow, send_intf, repeat=1):
        self.__addintf(send_intf)
        '''need modification'''
        cfg = '''
        interface {}
          no shutdown
        '''.format(send_intf)
        self.__tg.configure(cfg)
        self.__tg.execute('tgn clear all')
        self.__tg.execute('tgn ' + send_intf)
        self.__tg.execute('tgn add {}'.format(flow.get_template()))
        self.__tg.execute('tgn name {}'.format(flow.get_name()))
        for cmd in flow.get_config():
            self.__tg.execute('tgn ' + cmd)

        self.__tg.execute('tgn send {}'.format(repeat))
        self.__tg.execute('tgn on')
        self.__tg.sendline('tgn start send')
        '''find replacement'''
        self.__tg.expect('   Send process complete.', timeout=1000)

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
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {} fast-count on'.format(intf))
        self.add_filter('fast-count', flow, intf)

    def add_display_filter(self, flow, intf):
        self.__addintf(intf)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {} fast-count on'.format(intf))
        self.add_filter('display', flow, intf)

    def add_capture_filter(self, flow, intf):
        self.__addintf(intf)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {} fast-count on'.format(intf))
        self.add_filter('capture', flow, intf)

    def add_cap_buffer(self, intf):
        self.__addintf(intf)
        self.__tg.execute('pkts {} promiscuous on'.format(intf))
        self.__tg.execute('pkts {}'.format(intf))
        self.__tg.execute('pkts add 1000000')

    def start_pkts_count(self):
        self.__tg.execute('pkts start')

    def stop_pkts_count(self):
        self.__tg.execute('pkts stop')

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
