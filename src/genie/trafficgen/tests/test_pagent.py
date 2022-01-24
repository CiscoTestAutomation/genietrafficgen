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
