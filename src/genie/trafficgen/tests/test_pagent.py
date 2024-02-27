import os
import unittest
from unittest.mock import Mock, call

from pyats.topology import loader

import unicon
from unicon.plugins.tests.mock.mock_device_iosxe import MockDeviceTcpWrapperIOSXE

unicon.settings.Settings.POST_DISCONNECT_WAIT_SEC = 0
unicon.settings.Settings.GRACEFUL_DISCONNECT_WAIT_SEC = 0.2


class TestPagent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.md = MockDeviceTcpWrapperIOSXE(port=0, state='general_enable')
        cls.md.start()
        telnet_port = cls.md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port
        cls.dev = tb.devices.pagent

    def test_connect(self):
        dev = self.dev
        try:
            dev.connect()
            self.assertIsInstance(
                dev.cli.execute,
                unicon.plugins.generic.service_implementation.Execute)
            self.assertIsInstance(
                dev.cli.configure,
                unicon.plugins.generic.service_implementation.Configure)
            output = dev.execute('show version')
            self.assertIn('IOS-XE', output)
        finally:
            dev.disconnect()

    def test_connect_connect(self):
        dev = self.dev

        try:
            dev.connect()
            dev.connect()
            dev.disconnect()
            dev.connect()
        finally:
            dev.disconnect()

    @classmethod
    def tearDownClass(cls):
        cls.md.stop()


class TestPagentAPIs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.md = MockDeviceTcpWrapperIOSXE(port=0, state='general_enable')
        cls.md.start()
        telnet_port = cls.md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port
        cls.dev = tb.devices.pagent
        cls.dev.connect()
        cls.dev.tg.execute = Mock()
        cls.dev.tg.configure = Mock()
        cls.dev.tg.sendline = Mock()
        cls.dev.tg.expect = Mock()

    def setUp(self):
        dev = self.dev
        dev.tg.execute.reset_mock()
        dev.tg.configure.reset_mock()
        dev.tg.sendline.reset_mock()
        dev.tg.expect.reset_mock()

    def test_send_rawip(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0015'
        mac_dst = 'aabb.0011.0021'
        ip_src = '192.168.101.111'
        ip_dst = '239.1.101.3'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_rawip(interface=intf, mac_src=mac_src,
                       mac_dst=mac_dst, ip_src=ip_src,
                       ip_dst=ip_dst, pps=pps, vlanid=vlan,
                       count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add ip'),
            call('tgn name tg_ip'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0015'),
            call('tgn L2-dest-addr aabb.0011.0021'),
            call('tgn L3-src-addr 192.168.101.111'),
            call('tgn L3-dest-addr 239.1.101.3'),
            call('tgn data-length 18'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_start_pkt_count_rawip(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0016'
        mac_dst = 'aabb.0011.0021'
        ip_src = '192.168.101.111'
        ip_dst = '239.1.101.4'
        vlan = '105'

        dev.start_pkt_count_rawip(interface=intf, mac_src=mac_src,
                                  mac_dst=mac_dst, ip_src=ip_src,
                                  ip_dst=ip_dst, vlan_tag=vlan)

        dev.tg.execute.assert_has_calls([
            call('pkts clear all'),
            call('pkts filter clear filters'),
            call('pkts eth0 promiscuous off'),
            call('pkts eth0 fast-count off'),
            call('pkts eth0 promiscuous on'),
            call('pkts eth0 fast-count on'),
            call('pkts filter eth0'),
            call('pkts filter add ip fast-count in'),
            call('pkts filter name eth0_pgf'),
            call('pkts filter layer 2 ethernet'),
            call('pkts filter l2-shim is dot1q'),
            call('pkts filter l2-shim vlan-id 105'),
            call('pkts filter L2-src-addr aabb.0011.0016'),
            call('pkts filter L2-dest-addr aabb.0011.0021'),
            call('pkts filter L3-src-addr 192.168.101.111'),
            call('pkts filter L3-dest-addr 239.1.101.4'),
            call('pkts filter data-length 18'),
            call('pkts filter match start-at packet-start offset 0 length 54'),
            call('pkts filter match mask-start L3-ttl offset 0 length 4'),
            call('pkts filter match mask-data 0 00FF0000'),
            call('pkts filter active'),
            call('pkts start')
        ])

    def test_stop_pkt_count(self):
        dev = self.dev

        dev.stop_pkt_count(interface='eth0')

        dev.tg.execute.assert_has_calls([call('pkts stop')])

    def test_start_pkt_count_rawip_mcast(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0017'
        ip_src = '192.168.101.112'
        ip_dst = '239.1.101.5'
        vlan = '105'

        dev.start_pkt_count_rawip_mcast(interface=intf, mac_src=mac_src,
                                        ip_src=ip_src, ip_dst=ip_dst,
                                        vlan=vlan)

        dev.tg.execute.assert_has_calls([
            call('pkts clear all'),
            call('pkts filter clear filters'),
            call('pkts eth0 promiscuous off'),
            call('pkts eth0 fast-count off'),
            call('pkts eth0 promiscuous on'),
            call('pkts eth0 fast-count on'),
            call('pkts filter eth0'),
            call('pkts filter add ip fast-count in'),
            call('pkts filter name eth0_pgf'),
            call('pkts filter layer 2 ethernet'),
            call('pkts filter l2-shim is dot1q'),
            call('pkts filter l2-shim vlan-id 105'),
            call('pkts filter L2-src-addr aabb.0011.0017'),
            call('pkts filter L2-dest-addr 0100.5E01.6505'),
            call('pkts filter L3-src-addr 192.168.101.112'),
            call('pkts filter L3-dest-addr 239.1.101.5'),
            call('pkts filter data-length 18'),
            call('pkts filter match start-at packet-start offset 0 length 54'),
            call('pkts filter match mask-start L3-ttl offset 0 length 4'),
            call('pkts filter match mask-data 0 00FF0000'),
            call('pkts filter active'),
            call('pkts start')
        ])

    def test_send_rawip_mcast(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        ip_src = '192.168.101.113'
        ip_dst = '239.1.101.6'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_rawip_mcast(interface=intf, mac_src=mac_src,
                             ip_src=ip_src, ip_dst=ip_dst,
                             pps=pps, vlan=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add ip'),
            call('tgn name tg_ip'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0018'),
            call('tgn L2-dest-addr 0100.5E01.6506'),
            call('tgn L3-src-addr 192.168.101.113'),
            call('tgn L3-dest-addr 239.1.101.6'),
            call('tgn data-length 18'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_rawipv6(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0015'
        mac_dst = 'aabb.0011.0021'
        ip_src = '5000::1'
        ip_dst = 'FF06::278'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_rawipv6(interface=intf, mac_src=mac_src,
                       mac_dst=mac_dst, ipv6_src=ip_src,
                       ipv6_dst=ip_dst, pps=pps, vlanid=vlan,
                       count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add ipv6'),
            call('tgn name ipv6'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0015'),
            call('tgn L2-dest-addr aabb.0011.0021'),
            call('tgn L3-src-addr 5000::1'),
            call('tgn L3-dest-addr FF06::278'),
            call('tgn data-length 18'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_rawipv6_mcast(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0015'
        ip_src = '5000::1'
        ip_dst = 'FF06::278'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_rawipv6_mcast(interface=intf, mac_src=mac_src,
                               ipv6_src=ip_src, ipv6_dst=ip_dst,
                               pps=pps, vlan=vlan,
                               count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add ipv6'),
            call('tgn name ipv6'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0015'),
            call('tgn L2-dest-addr 3333.0000.0278'),
            call('tgn L3-src-addr 5000::1'),
            call('tgn L3-dest-addr FF06::278'),
            call('tgn data-length 18'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_start_pkt_count_rawipv6(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0016'
        mac_dst = 'aabb.0011.0021'
        ip_src = '5000::1'
        ip_dst = 'FF06::277'
        vlan = '105'

        dev.start_pkt_count_rawipv6(interface=intf, mac_src=mac_src,
                                  mac_dst=mac_dst, ipv6_src=ip_src,
                                  ipv6_dst=ip_dst, vlan_tag=vlan)

        dev.tg.execute.assert_has_calls([
            call('pkts clear all'),
            call('pkts filter clear filters'),
            call('pkts eth0 promiscuous off'),
            call('pkts eth0 fast-count off'),
            call('pkts eth0 promiscuous on'),
            call('pkts eth0 fast-count on'),
            call('pkts filter eth0'),
            call('pkts filter add ipv6 fast-count in'),
            call('pkts filter name eth0_pgf'),
            call('pkts filter layer 2 ethernet'),
            call('pkts filter l2-shim is dot1q'),
            call('pkts filter l2-shim vlan-id 105'),
            call('pkts filter L2-src-addr aabb.0011.0016'),
            call('pkts filter L2-dest-addr aabb.0011.0021'),
            call('pkts filter L3-src-addr 5000::1'),
            call('pkts filter L3-dest-addr FF06::277'),
            call('pkts filter data-length 18'),
            call('pkts filter match start-at packet-start offset 0 length 74'),
            call('pkts filter match mask-start L3-hop-limit offset 0 length 1'),
            call('pkts filter match mask-data 0 00'),
            call('pkts filter active'),
            call('pkts start')
        ])

    def test_start_pkt_count_rawipv6_mcast(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0016'
        ip_src = '5000::1'
        ip_dst = 'FF06::277'
        vlan = '105'

        dev.start_pkt_count_rawipv6_mcast(interface=intf, mac_src=mac_src,
                                          ipv6_src=ip_src, ipv6_dst=ip_dst,
                                          vlan=vlan)

        dev.tg.execute.assert_has_calls([
            call('pkts clear all'),
            call('pkts filter clear filters'),
            call('pkts eth0 promiscuous off'),
            call('pkts eth0 fast-count off'),
            call('pkts eth0 promiscuous on'),
            call('pkts eth0 fast-count on'),
            call('pkts filter eth0'),
            call('pkts filter add ipv6 fast-count in'),
            call('pkts filter name eth0_pgf'),
            call('pkts filter layer 2 ethernet'),
            call('pkts filter l2-shim is dot1q'),
            call('pkts filter l2-shim vlan-id 105'),
            call('pkts filter L2-src-addr aabb.0011.0016'),
            call('pkts filter L2-dest-addr 3333.0000.0277'),
            call('pkts filter L3-src-addr 5000::1'),
            call('pkts filter L3-dest-addr FF06::277'),
            call('pkts filter data-length 18'),
            call('pkts filter match start-at packet-start offset 0 length 74'),
            call('pkts filter match mask-start L3-hop-limit offset 0 length 1'),
            call('pkts filter match mask-data 0 00'),
            call('pkts filter active'),
            call('pkts start')
        ])

    def test_send_arp_reqeust(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = '0051.a101.0011'
        ip_src = '192.168.101.11'
        ip_target = '192.168.101.12'
        pps = 100
        vlan = '101'
        count = '5'

        dev.send_arp_request(interface=intf, mac_src=mac_src,
                             ip_src=ip_src, ip_target=ip_target,
                             pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add arp'),
            call('tgn name arpreq'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 101'),
            call('tgn L2-src-addr 0051.a101.0011'),
            call('tgn L2-dest-addr FFFF.FFFF.FFFF'),
            call('tgn L3-sender-haddr 0051.a101.0011'),
            call('tgn L3-sender-paddr 192.168.101.11'),
            call('tgn L3-target-haddr FFFF.FFFF.FFFF'),
            call('tgn L3-target-paddr 192.168.101.12'),
            call('tgn data-length 18'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_garp(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = '0051.a101.0011'
        ip_src = '192.168.101.11'
        ip_target = '192.168.101.11'
        pps = 100
        vlan = '101'
        count = '5'

        dev.send_arp_request(interface=intf, mac_src=mac_src,
                             ip_src=ip_src, ip_target=ip_target,
                             pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add arp'),
            call('tgn name arpreq'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 101'),
            call('tgn L2-src-addr 0051.a101.0011'),
            call('tgn L2-dest-addr FFFF.FFFF.FFFF'),
            call('tgn L3-sender-haddr 0051.a101.0011'),
            call('tgn L3-sender-paddr 192.168.101.11'),
            call('tgn L3-target-haddr 0000.0000.0000'),
            call('tgn L3-operation 2'),
            call('tgn L3-target-paddr 192.168.101.11'),
            call('tgn data-length 18'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_ndp_ns(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        ip_src = '2001:105::11'
        ip_dst = '2001:105::12'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_ndp_ns(interface=intf, mac_src=mac_src,
                        ip_src=ip_src, ip_dst=ip_dst,
                        pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name ndpns'),
            call('tgn length auto'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0018'),
            call('tgn L2-dest-addr 3333.ff00.0012'),
            call('tgn L3-traffic-class 224'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr ff02::1:ff00:0012'),
            call('tgn L3-hop-limit 255'),
            call('tgn data 0 00000000200101050000000000000000000000120101aabb00110018'),
            call('tgn L4-type 135'),
            call('tgn L4-code 0'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_ndp_na_solicited(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        mac_dst = 'aabb.0011.0019'
        ip_src = '2001:105::11'
        ip_dst = '2001:105::12'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_ndp_na(interface=intf, mac_src=mac_src,
                        mac_dst=mac_dst, ip_src=ip_src, ip_dst=ip_dst,
                        pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name ndpna'),
            call('tgn length auto'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0018'),
            call('tgn L2-dest-addr aabb.0011.0019'),
            call('tgn L3-traffic-class 224'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr 2001:105::12'),
            call('tgn L3-hop-limit 255'),
            call('tgn L4-type 136'),
            call('tgn L4-code 0'),
            call('tgn data 0 60000000200101050000000000000000000000110201aabb00110018'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_ndp_na_unsolicited(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        mac_dst = 'aabb.0011.0019'
        ip_src = '2001:105::11'
        ip_dst = 'FF02::1'
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_ndp_na(interface=intf, mac_src=mac_src,
                        mac_dst=mac_dst, ip_src=ip_src, ip_dst=ip_dst,
                        pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name ndpna'),
            call('tgn length auto'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0018'),
            call('tgn L2-dest-addr 3333.ff00.0001'),
            call('tgn L3-traffic-class 224'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::1'),
            call('tgn L3-hop-limit 255'),
            call('tgn L4-type 136'),
            call('tgn L4-code 0'),
            call('tgn data 0 10000000200101050000000000000000000000110201aabb00110018'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_igmpv2_query_general(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        ip_src = '192.168.1.11'
        max_resp = 100
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_igmpv2_query_general(interface=intf, mac_src=mac_src,
                                      ip_src=ip_src, max_resp=max_resp,
                                      pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name igmpq'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0018'),
            call('tgn L2-dest-addr 0100.5E00.0001'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.1'),
            call('tgn L4-version 1'),
            call('tgn L4-type 1'),
            call('tgn L4-max-resp 100'),
            call('tgn L4-group-address 0.0.0.0'),
            call('tgn data-length 0'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_igmpv3_source_group_report_general(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '192.168.1.11'
        groupip = '234.1.1.11'
        filter_mode='include'
        max_resp = 100
        vlanid = '105'

        client_handler = dev.create_igmp_client(interface=intf,
                                                clientip=clientip,
                                                version=3,
                                                vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip)
        source_handler = dev.create_multicast_source(clientip)

        handler = dev.igmp_client_add_group(client_handler=client_handler,
                                            group_handler=group_handler,
                                            source_handler=source_handler,
                                            filter_mode=filter_mode)

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='start')

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 01000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='stop')

        dev.igmp_client_del_group(client_handler=client_handler,
                                  handler=handler)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)


    def test_send_igmpv3_source_group_report_include_allow(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '192.168.1.11'
        groupip = '234.1.1.11'
        filter_mode='include'
        max_resp = 100
        vlanid = '105'
        allowip = '192.168.2.12'

        client_handler = dev.create_igmp_client(interface=intf,
                                                clientip=clientip,
                                                version=3,
                                                vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip)
        source_handler = dev.create_multicast_source(clientip)

        handler = dev.igmp_client_add_group(client_handler=client_handler,
                                            group_handler=group_handler,
                                            source_handler=source_handler,
                                            filter_mode=filter_mode)

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 01000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        source_handler_allow = dev.create_multicast_source(allowip)
        handler_allow = dev.igmp_client_group_allow_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler_allow,
        )

        # Allow
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 05000001EA01010BC0A8020C'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='stop')

        # Leave (by BLOCKs)
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 06000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all'),
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 06000001EA01010BC0A8020C'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_del_group(client_handler=client_handler,
                                  handler=handler)
        dev.igmp_client_del_group(client_handler=client_handler,
                                  handler=handler_allow)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)
        dev.delete_multicast_source(source_handler_allow)

    def test_send_igmpv3_source_group_report_exclude_allow(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '192.168.1.11'
        groupip = '234.1.1.11'
        filter_mode='exclude'
        max_resp = 100
        vlanid = '105'

        client_handler = dev.create_igmp_client(interface=intf,
                                                clientip=clientip,
                                                version=3,
                                                vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip)
        source_handler = dev.create_multicast_source(clientip)

        handler = dev.igmp_client_add_group(client_handler=client_handler,
                                            group_handler=group_handler,
                                            source_handler=source_handler,
                                            filter_mode=filter_mode)

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 02000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        handler_allow = dev.igmp_client_group_allow_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler,
            handler=handler,
        )

        # Allow
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 05000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='stop')

        # Leave (by TO_IN)
        dev.tg.execute.assert_has_calls([
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all'),
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 8'),
            call('tgn data 0 03000000EA01010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_del_group(client_handler=client_handler,
                                  handler=handler_allow)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)

    def test_send_igmpv3_source_group_report_include_block(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '192.168.1.11'
        groupip = '234.1.1.11'
        filter_mode='include'
        max_resp = 100
        vlanid = '105'

        client_handler = dev.create_igmp_client(interface=intf,
                                                clientip=clientip,
                                                version=3,
                                                vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip)
        source_handler = dev.create_multicast_source(clientip)

        handler = dev.igmp_client_add_group(client_handler=client_handler,
                                            group_handler=group_handler,
                                            source_handler=source_handler,
                                            filter_mode=filter_mode)

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 01000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_group_block_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler,
            handler=handler,
        )

        # Block/Leave
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 06000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='stop')

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)

    def test_send_igmpv3_source_group_report_exclude_block(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '192.168.1.11'
        groupip = '234.1.1.11'
        filter_mode='exclude'
        max_resp = 100
        vlanid = '105'
        blockip = '192.168.2.12'

        client_handler = dev.create_igmp_client(interface=intf,
                                                clientip=clientip,
                                                version=3,
                                                vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip)
        source_handler = dev.create_multicast_source(clientip)

        handler = dev.igmp_client_add_group(client_handler=client_handler,
                                            group_handler=group_handler,
                                            source_handler=source_handler,
                                            filter_mode=filter_mode)

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 02000001EA01010BC0A8010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        source_handler_block = dev.create_multicast_source(blockip)
        handler_block = dev.igmp_client_group_block_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler_block,
        )

        # Block
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 12'),
            call('tgn data 0 06000001EA01010BC0A8020C'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_control(interface=intf, client_handler=client_handler,
                                mode='stop')

        # Leave (by TO_IN)
        dev.tg.execute.assert_has_calls([
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all'),
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add igmp'),
            call('tgn name c_1'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb28.010B'),
            call('tgn L2-dest-addr 0100.5E00.0016'),
            call('tgn L3-src-addr 192.168.1.11'),
            call('tgn L3-dest-addr 224.0.0.22'),
            call('tgn L4-version 2'),
            call('tgn L4-type 2'),
            call('tgn L4-max-resp 0'),
            call('tgn L4-group-address 0.0.0.1'),
            call('tgn data-length 8'),
            call('tgn data 0 03000000EA01010B'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.igmp_client_del_group(client_handler=client_handler,
                                  handler=handler)
        dev.igmp_client_del_group(client_handler=client_handler,
                                  handler=handler_block)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)
        dev.delete_multicast_source(source_handler_block)


    def test_send_mldv1_query_general(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        ip_src = '2001:105::11'
        max_resp = 100
        pps = 100
        vlan = '105'
        count = '5'

        dev.send_mldv1_query_general(interface=intf, mac_src=mac_src,
                                      ip_src=ip_src, max_resp=max_resp,
                                      pps=pps, vlan_tag=vlan, count=count)

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name mldv1gq'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.0011.0018'),
            call('tgn L2-dest-addr 3333.0000.0001'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::1'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 130'),
            call('tgn L4-message 0 0064000000000000000000000000000000000000'),
            call('tgn on'),
            call('tgn rate 100'),
            call('tgn send 5'),
            call('tgn clear all')])

    def test_send_mldv2_source_group_report_general(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '2001:105::11'
        groupip = 'FF0E:11::11'
        filter_mode='include'
        max_resp = 100
        vlanid = '105'

        client_handler = dev.create_mld_client(interface=intf,
                                               clientip=clientip,
                                               version=2,
                                               vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip, ip_prefix_len=128)
        source_handler = dev.create_multicast_source(clientip, ip_prefix_len=128)

        handler = dev.mld_client_add_group(client_handler=client_handler,
                                           group_handler=group_handler,
                                           source_handler=source_handler,
                                           filter_mode=filter_mode)

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='start')

        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000101000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='stop')

        dev.mld_client_del_group(client_handler=client_handler,
                                 handler=handler)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)


    def test_send_mldv2_source_group_report_include_allow(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '2001:105::11'
        groupip = 'FF0E:11::11'
        filter_mode='include'
        max_resp = 100
        vlanid = '105'
        allowip = '2001:105::12'

        client_handler = dev.create_mld_client(interface=intf,
                                               clientip=clientip,
                                               version=2,
                                               vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip, ip_prefix_len=128)
        source_handler = dev.create_multicast_source(clientip, ip_prefix_len=128)

        handler = dev.mld_client_add_group(client_handler=client_handler,
                                           group_handler=group_handler,
                                           source_handler=source_handler,
                                           filter_mode=filter_mode)

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000101000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        source_handler_allow = dev.create_multicast_source(allowip,
                                                           ip_prefix_len=128)
        handler_allow = dev.mld_client_group_allow_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler_allow,
        )

        # Allow
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000105000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000012'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='stop')

        # Leave (by BLOCKs)
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000106000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all'),
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000106000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000012'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_del_group(client_handler=client_handler,
                                 handler=handler)
        dev.mld_client_del_group(client_handler=client_handler,
                                 handler=handler_allow)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)
        dev.delete_multicast_source(source_handler_allow)

    def test_send_mldv2_source_group_report_exclude_allow(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '2001:105::11'
        groupip = 'FF0E:11::11'
        filter_mode='exclude'
        max_resp = 100
        vlanid = '105'

        client_handler = dev.create_mld_client(interface=intf,
                                               clientip=clientip,
                                               version=2,
                                               vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip, ip_prefix_len=128)
        source_handler = dev.create_multicast_source(clientip, ip_prefix_len=128)

        handler = dev.mld_client_add_group(client_handler=client_handler,
                                           group_handler=group_handler,
                                           source_handler=source_handler,
                                           filter_mode=filter_mode)

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000102000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        handler_allow = dev.mld_client_group_allow_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler,
            handler=handler,
        )

        # Allow
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000105000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='stop')

        # Leave (by TO_IN)
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000103000000FF0E00110000000000000000' +\
                 '00000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_del_group(client_handler=client_handler,
                                 handler=handler_allow)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)

    def test_send_mldv2_source_group_report_include_block(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '2001:105::11'
        groupip = 'FF0E:11::11'
        filter_mode='include'
        max_resp = 100
        vlanid = '105'

        client_handler = dev.create_mld_client(interface=intf,
                                               clientip=clientip,
                                               version=2,
                                               vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip, ip_prefix_len=128)
        source_handler = dev.create_multicast_source(clientip, ip_prefix_len=128)

        handler = dev.mld_client_add_group(client_handler=client_handler,
                                           group_handler=group_handler,
                                           source_handler=source_handler,
                                           filter_mode=filter_mode)

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000101000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_group_block_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler,
            handler=handler,
        )

        # Block/Leave
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000106000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='stop')

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)

    def test_send_mldv2_source_group_report_exclude_block(self):
        dev = self.dev

        intf = 'eth0'
        mac_src = 'aabb.0011.0018'
        clientip = '2001:105::11'
        groupip = 'FF0E:11::11'
        filter_mode='exclude'
        max_resp = 100
        vlanid = '105'
        blockip = '2001:105::12'

        client_handler = dev.create_mld_client(interface=intf,
                                               clientip=clientip,
                                               version=2,
                                               vlanid=vlanid)
        group_handler = dev.create_multicast_group(groupip, ip_prefix_len=128)
        source_handler = dev.create_multicast_source(clientip, ip_prefix_len=128)

        handler = dev.mld_client_add_group(client_handler=client_handler,
                                           group_handler=group_handler,
                                           source_handler=source_handler,
                                           filter_mode=filter_mode)

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='start')

        # Join
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000102000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        source_handler_block = dev.create_multicast_source(blockip,
                                                           ip_prefix_len=128)
        handler_block = dev.mld_client_group_block_source(
            client_handler=client_handler,
            group_handler=group_handler,
            source_handler=source_handler_block,
        )

        # Block
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000106000001FF0E00110000000000000000' +\
                 '0000001120010105000000000000000000000012'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_control(interface=intf, client_handler=client_handler,
                               mode='stop')

        # Leave (by TO_IN)
        dev.tg.execute.assert_has_calls([
            call('tgn clear all'),
            call('tgn eth0'),
            call('tgn add icmpv6'),
            call('tgn name c_2'),
            call('tgn layer 2 ethernet'),
            call('tgn l2-shim is dot1q'),
            call('tgn l2-shim vlan-id 105'),
            call('tgn L2-src-addr aabb.bb00.0011'),
            call('tgn L2-dest-addr 3333.0000.0016'),
            call('tgn L3-src-addr 2001:105::11'),
            call('tgn L3-dest-addr FF02::16'),
            call('tgn L3-hop-limit 1'),
            call('tgn L3-next-header 0'),
            call('tgn L3-header total 1 modules'),
            call('tgn L3-header 0 is hop_by_hop'),
            call('tgn L3-header 0 next-header 58'),
            call('tgn L3-header 0 option 0 0 0502'),
            call('tgn L4-type 143'),
            call('tgn L4-message 0 0000000103000000FF0E00110000000000000000' +\
                 '00000011'),
            call('tgn on'),
            call('tgn rate 1'),
            call('tgn send 1'),
            call('tgn clear all')])

        dev.mld_client_del_group(client_handler=client_handler,
                                 handler=handler)
        dev.mld_client_del_group(client_handler=client_handler,
                                 handler=handler_block)

        dev.delete_multicast_group(group_handler)
        dev.delete_multicast_source(source_handler)
        dev.delete_multicast_source(source_handler_block)


    def test_start_pkt_count_arp(self):
        dev = self.dev


        intf = 'eth0'
        mac_src = 'aabb.0011.0111'
        mac_dst = 'aabb.0011.0222'
        ip_src = '192.168.101.11'
        ip_target = '192.168.101.22'
        vlan = '105'

        dev.start_pkt_count_arp(interface=intf,
                                 mac_src=mac_src, mac_dst=mac_dst,
                                 src_ip=ip_src, dst_ip=ip_target,
                                 vlan_tag=vlan)

        dev.tg.execute.assert_has_calls([
            call('pkts clear all'),
            call('pkts filter clear filters'),
            call('pkts eth0 promiscuous off'),
            call('pkts eth0 fast-count off'),
            call('pkts eth0 promiscuous on'),
            call('pkts eth0 fast-count on'),
            call('pkts filter eth0'),
            call('pkts filter add arp fast-count in'),
            call('pkts filter name eth0_pgf'),
            call('pkts filter layer 2 ethernet'),
            call('pkts filter l2-shim is dot1q'),
            call('pkts filter l2-shim vlan-id 105'),
            call('pkts filter L2-src-addr aabb.0011.0111'),
            call('pkts filter L2-dest-addr aabb.0011.0222'),
            call('pkts filter L3-sender-haddr aabb.0011.0111'),
            call('pkts filter L3-sender-paddr 192.168.101.11'),
            call('pkts filter L3-target-haddr aabb.0011.0222'),
            call('pkts filter L3-target-paddr 192.168.101.22'),
            call('pkts filter match start-at packet-start offset 0 length 34'),
            call('pkts filter active'),
            call('pkts start')
        ])

    def test_start_pkt_count_ndp(self):
        dev = self.dev


        intf = 'eth0'
        mac_src = 'aabb.0011.0111'
        mac_dst = 'aabb.0011.0222'
        ip_src = '2001:11::11'
        ip_target = '2001:11::22'
        vlan = '105'

        dev.start_pkt_count_nd(interface=intf,
                                 mac_src=mac_src, mac_dst=mac_dst,
                                 src_ip=ip_src, dst_ip=ip_target,
                                 vlan_tag=vlan)

        dev.tg.execute.assert_has_calls([
            call('pkts clear all'),
            call('pkts filter clear filters'),
            call('pkts eth0 promiscuous off'),
            call('pkts eth0 fast-count off'),
            call('pkts eth0 promiscuous on'),
            call('pkts eth0 fast-count on'),
            call('pkts filter eth0'),
            call('pkts filter add icmpv6 fast-count in'),
            call('pkts filter name eth0_pgf'),
            call('pkts filter length auto'),
            call('pkts filter layer 2 ethernet'),
            call('pkts filter l2-shim is dot1q'),
            call('pkts filter l2-shim vlan-id 105'),
            call('pkts filter L2-src-addr aabb.0011.0111'),
            call('pkts filter L2-dest-addr aabb.0011.0222'),
            call('pkts filter L3-traffic-class 224'),
            call('pkts filter L3-src-addr 2001:11::11'),
            call('pkts filter L3-dest-addr ff02::1:ff00:0022'),
            call('pkts filter L3-hop-limit 255'),
            call('pkts filter data 0 00000000200100110000000000000000000000220101aabb00110111'),
            call('pkts filter L4-type 135'),
            call('pkts filter L4-code 0'),
            call('pkts filter match start-at packet-start offset 0 length 74'),
            call('pkts filter active'),
            call('pkts start')
        ])

    def test_dhcpv4_emulator_client(self):
        dev = self.dev

        intf = 'eth0'
        vlan = '105'

        dev.add_dhcpv4_emulator_client(interface=intf, vlan_id=vlan)

        dev.tg.execute.assert_has_calls([
            call('dce stop'),
            call('dce prompt static'),
            call('dce eth0'),
            call('dce add client'),
            call('dce set dot1q 105'),
            call('dce start'),
            call('dce show all'),
            call('dce end'),
        ])

    def test_dhcpv6_emulator_client(self):
        dev = self.dev

        intf = 'eth0'
        vlan = '105'

        dev.add_dhcpv6_emulator_client(interface=intf, vlan_id=vlan)

        dev.tg.execute.assert_has_calls([
            call('dce stop'),
            call('dce prompt static'),
            call('dce eth0'),
            call('dce add client ipv6'),
            call('dce set dot1q 105'),
            call('dce start'),
            call('dce show all'),
            call('dce end'),
        ])

    def test_get_dhcp_binding(self):
        dev = self.dev

        intf = 'eth0'

        dev.get_dhcp_binding(interface=intf)

        dev.tg.execute.assert_has_calls([
            call('dce show all'),
        ])

    @classmethod
    def tearDownClass(cls):
        cls.dev.disconnect()
        cls.md.stop()

class TestIolPagent(unittest.TestCase):

    def test_iol_pagent_start_send(self):
        md = MockDeviceTcpWrapperIOSXE(port=0, state='enable', mock_data_dir='mock_data', hostname='pagent')
        md.start()
        telnet_port = md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)

        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port

        dev = tb.devices.pagent
        try:
            dev.connect()
            dev.send_rawip(interface='Gi0/0', mac_src='00:de:ad:be:ef:ff', mac_dst='', ip_src='', ip_dst='')
        finally:
            md.stop()


    def test_verify_dhcp_client_binding(self):
        md = MockDeviceTcpWrapperIOSXE(port=0, state='enable', mock_data_dir='mock_data', hostname='pagent')
        md.start()
        telnet_port = md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)

        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port

        dev = tb.devices.pagent
        intf = 'eth0'
        result = False
        expected = True

        try:
            dev.connect()
            result = dev.verify_dhcp_client_binding(interface=intf)
        finally:
            md.stop()

        self.assertEqual(result, expected)

    def test_get_dhcpv4_binding_address(self):
        md = MockDeviceTcpWrapperIOSXE(port=0, state='enable', mock_data_dir='mock_data', hostname='pagent')
        md.start()
        telnet_port = md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)

        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port

        dev = tb.devices.pagent
        intf = 'eth0'
        result = ""
        expected = "192.168.111.1"

        try:
            dev.connect()
            result = dev.get_dhcpv4_binding_address(interface=intf)
        finally:
            md.stop()

        self.assertEqual(result, expected)

    def test_get_dhcpv6_binding_address(self):
        md = MockDeviceTcpWrapperIOSXE(port=0, state='enable', mock_data_dir='mock_data', hostname='pagent')
        md.start()
        telnet_port = md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)

        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port

        dev = tb.devices.pagent
        intf = 'eth0'
        result = ""
        expected = "2001:111::41D8:472C:990A:A938"

        try:
            dev.connect()
            result = dev.get_dhcpv6_binding_address(interface=intf)
        finally:
            md.stop()

        self.assertEqual(result, expected)
