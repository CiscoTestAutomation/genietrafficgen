import os
import json
import logging
import shutil
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyats.topology import loader

from genie.harness.exceptions import GenieTgnError
from genie.trafficgen.otg import implementation

TESTBED = os.path.join(os.path.dirname(__file__), 'testbed_otg.yaml')


class OtgTestCase(unittest.TestCase):
    '''Connects a mock-transport OTG device for each test.'''

    device_name = 'otg1'

    @classmethod
    def setUpClass(cls):
        cls.testbed = loader.load(TESTBED)

    def setUp(self):
        self.dev = self.testbed.devices[self.device_name]
        self.tgn = self.dev.instantiate(via='tgn', alias='tgn')
        self.tgn.connect()

    def tearDown(self):
        self.tgn.disconnect()
        self.dev.destroy()

    def add_flow(self, interface='port1', src_ip='10.1.1.2', dst_ip='10.1.2.2',
                 **kwargs):
        kwargs.setdefault('l4_protocol', 'udp')
        kwargs.setdefault('transmit_mode', 'continuous')
        kwargs.setdefault('pps', 1000)
        return self.tgn.configure_ipv4_data_traffic(
            interface=interface, src_ip=src_ip, dst_ip=dst_ip, **kwargs)

    def flow(self, name):
        return next(f for f in self.tgn.config.flows if f.name == name)


class TestOtgAbstraction(unittest.TestCase):
    '''Genie abstraction lookup and testbed connection key handling.'''

    @classmethod
    def setUpClass(cls):
        cls.testbed = loader.load(TESTBED)

    def test_direct_class_resolves(self):
        dev = self.testbed.devices.otg1
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Otg')
        self.assertFalse(dev.default.connected)

    def test_abstraction_token_resolves(self):
        dev = self.testbed.devices.otg2
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Otg')
        self.assertFalse(dev.default.connected)

    def test_mock_transport_defaults(self):
        dev = self.testbed.devices.otg1
        dev.instantiate()
        self.assertEqual(dev.default.transport, 'mock')
        self.assertEqual(dev.default.location, 'mock')

    def test_http_location_built_from_ip_and_port(self):
        dev = self.testbed.devices.otg3
        dev.instantiate()
        self.assertEqual(dev.default.transport, 'https')
        self.assertEqual(dev.default.location, 'https://192.0.0.10:8443')

    def test_grpc_location_passthrough(self):
        dev = self.testbed.devices.otg4
        dev.instantiate()
        self.assertEqual(dev.default.transport, 'grpc')
        self.assertEqual(dev.default.location, '192.0.0.10:40051')

    def test_certificate_verification_is_secure_by_default(self):
        dev = self.testbed.devices.otg3
        dev.instantiate()
        self.assertTrue(dev.default.verify_certificate)

    def test_certificate_verification_can_be_disabled(self):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg3
        dev.connections.tgn['verify_certificate'] = False
        tgn = dev.instantiate(via='tgn', alias='tgn')
        self.assertFalse(tgn.verify_certificate)

    def test_unsupported_transport_is_rejected(self):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg1
        dev.connections.tgn['transport'] = 'carrier-pigeon'
        with self.assertRaises(GenieTgnError):
            dev.instantiate(via='tgn', alias='tgn')


class TestSnappiIsOptional(unittest.TestCase):
    '''snappi must stay an opt-in dependency of the plugin.'''

    def test_import_does_not_pull_snappi(self):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, '-c',
             'import sys; import genie.trafficgen.otg; '
             "print('snappi' in sys.modules, 'grpc' in sys.modules)"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('False False', result.stdout)

    def test_missing_snappi_raises_actionable_error(self):
        from genie.trafficgen.otg import implementation

        with patch.dict('sys.modules', {'snappi': None}):
            with self.assertRaises(GenieTgnError) as ctx:
                implementation.import_snappi()
        self.assertIn('genie.trafficgen[otg]', str(ctx.exception))

    def test_non_mock_transport_requires_snappi(self):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg3
        tgn = dev.instantiate(via='tgn', alias='tgn')
        with patch.dict('sys.modules', {'snappi': None}):
            with self.assertRaises(GenieTgnError):
                tgn.connect()
        self.assertFalse(tgn.connected)


class TestConnectionLifecycle(OtgTestCase):

    def test_connect_populates_ports_from_testbed(self):
        # otg1 has no interfaces; otg2 carries port1/port2 in the topology.
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg2
        tgn = dev.instantiate(via='tgn', alias='tgn')
        tgn.connect()
        self.assertEqual([p.name for p in tgn.config.ports], ['port1', 'port2'])
        tgn.disconnect()

    def test_connect_is_idempotent(self):
        api = self.tgn.api
        self.assertTrue(self.tgn.connect())
        self.assertIs(self.tgn.api, api)

    def test_disconnect_is_idempotent(self):
        self.assertTrue(self.tgn.disconnect())
        self.assertTrue(self.tgn.disconnect())
        self.assertFalse(self.tgn.connected)

    def test_disconnect_clears_session_state(self):
        self.add_flow()
        self.tgn.disconnect()
        self.assertIsNone(self.tgn.api)
        self.assertIsNone(self.tgn.config)
        self.assertEqual(self.tgn.get_traffic_stream_names.__self__._traffic_streams, [])

    def test_disconnect_stops_controller_traffic_after_local_reset(self):
        """Replacing the local config must not strand traffic on the controller.

        Starting traffic pushes flows to the controller. Adopting a fresh local
        config afterwards empties the local view but leaves those flows running
        remotely, so disconnect must still stop them.
        """
        otg = self.tgn.get_traffic_stream_names.__self__
        self.add_flow()
        self.tgn.start_traffic()
        self.assertTrue(otg._controller_has_flows)
        self.tgn.new_config()
        self.assertTrue(otg._controller_has_flows)
        with patch.object(type(otg), 'stop_traffic') as stop:
            self.tgn.disconnect()
        stop.assert_called_once()

    def test_disconnect_stops_raw_arp_traffic(self):
        """A raw ARP flow pushed directly to the controller is cleaned up."""
        otg = self.tgn.get_traffic_stream_names.__self__
        self.add_flow()
        ipv4 = self.tgn.config.devices[0].ethernets[0].ipv4_addresses[0]
        flow_name = self.tgn.send_arp_request(
            interface='port1', mac_src='00:11:22:33:44:55',
            ip_src=ipv4.address, ip_target=ipv4.gateway, count=1000000)
        self.assertIn(flow_name, self.tgn.get_traffic_stream_names())
        self.assertTrue(otg._controller_has_flows)
        with patch.object(type(otg), 'stop_traffic') as stop:
            self.tgn.disconnect()
        stop.assert_called_once()

    def test_disconnect_without_controller_flows_skips_stop(self):
        """A connection that never pushed flows has nothing to stop remotely."""
        otg = self.tgn.get_traffic_stream_names.__self__
        self.assertFalse(otg._controller_has_flows)
        with patch.object(type(otg), 'stop_traffic') as stop:
            self.tgn.disconnect()
        stop.assert_not_called()

    def test_remove_configuration_clears_controller_flow_tracking(self):
        """Removing the controller configuration also clears the flow flag."""
        otg = self.tgn.get_traffic_stream_names.__self__
        self.add_flow()
        self.tgn.start_traffic()
        self.assertTrue(otg._controller_has_flows)
        self.tgn.remove_configuration(wait_time=0)
        self.assertFalse(otg._controller_has_flows)

    def test_clear_traffic_clears_controller_flow_tracking(self):
        """Clearing the applied configuration leaves no remote flows to stop."""
        otg = self.tgn.get_traffic_stream_names.__self__
        self.add_flow()
        self.tgn.start_traffic()
        self.assertTrue(otg._controller_has_flows)
        self.tgn.clear_traffic()
        self.assertFalse(otg._controller_has_flows)

    def test_operations_require_a_connection(self):
        self.tgn.disconnect()
        for operation in (lambda: self.add_flow(),
                          lambda: self.tgn.start_traffic(),
                          lambda: self.tgn.get_stats(),
                          lambda: self.tgn.new_config()):
            with self.assertRaises(GenieTgnError):
                operation()

    def test_engine_exposed_in_mock_mode(self):
        self.assertIsNotNone(self.tgn.engine)


class TestLegacyTranslation(OtgTestCase):

    device_name = 'otg2'

    def test_ipv4_flow_headers_and_rate(self):
        name = self.add_flow(l4_protocol='tcp', pps=750,
                             src_port=1234, dst_port=4321)
        flow = self.flow(name)
        self.assertEqual([type(h).__name__ for h in flow.packet],
                         ['EthernetHeader', 'Ipv4Header', 'TcpHeader'])
        self.assertEqual(flow.packet[1].src.value, '10.1.1.2')
        self.assertEqual(flow.packet[1].dst.value, '10.1.2.2')
        self.assertEqual(flow.packet[2].src_port.value, 1234)
        self.assertEqual(flow.rate.pps, 750)
        self.assertTrue(flow.metrics.enable)

    def test_ipv6_flow_headers(self):
        name = self.tgn.configure_ipv6_data_traffic(
            interface='port1', src_ip='2001:db8:1::2', dst_ip='2001:db8:2::2',
            l4_protocol='udp', transmit_mode='continuous', pps=100)
        flow = self.flow(name)
        self.assertEqual([type(h).__name__ for h in flow.packet],
                         ['EthernetHeader', 'Ipv6Header', 'UdpHeader'])
        self.assertEqual(flow.packet[1].src.value, '2001:db8:1::2')

    def endpoints(self, name):
        return self.tgn.translation_engine.flow_endpoints(self.flow(name))

    def test_rx_port_inferred_from_destination_subnet(self):
        self.assertEqual(self.endpoints(self.add_flow(dst_ip='10.1.2.2')),
                         ('port1', 'port2'))

    def test_rx_port_explicit_keyword_wins(self):
        name = self.add_flow(dst_ip='10.1.2.2', rx_interface='port1')
        # Same tx and rx port means the destination is not emulated separately.
        self.assertEqual(self.flow(name).tx_rx.port.rx_name, 'port1')

    def test_rx_port_falls_back_to_next_configured_port(self):
        self.assertEqual(self.endpoints(self.add_flow(dst_ip='203.0.113.9')),
                         ('port1', 'port2'))

    def test_routed_flow_binds_device_endpoints(self):
        flow = self.flow(self.add_flow())
        self.assertEqual(flow.tx_rx.choice, 'device')
        self.assertEqual(flow.tx_rx.device.tx_names, ['ipv4_dev_port1_10_1_1_2'])
        self.assertEqual(flow.tx_rx.device.rx_names, ['ipv4_dev_port2_10_1_2_2'])

    def test_destination_emulation_can_be_disabled(self):
        flow = self.flow(self.add_flow(emulate_destination=False))
        self.assertEqual(flow.tx_rx.choice, 'port')
        self.assertEqual(flow.tx_rx.port.tx_name, 'port1')
        self.assertEqual(flow.tx_rx.port.rx_name, 'port2')
        self.assertEqual(len(self.tgn.config.devices), 1)

    def test_destination_endpoint_gets_its_own_gateway(self):
        self.add_flow()
        gateways = sorted(
            address.gateway
            for device in self.tgn.config.devices
            for eth in device.ethernets
            for address in eth.ipv4_addresses)
        self.assertEqual(gateways, ['10.1.1.1', '10.1.2.1'])

    def test_emulated_device_synthesized_for_arp(self):
        self.add_flow()
        device = self.tgn.config.devices[0]
        self.assertEqual(device.ethernets[0].connection.port_name, 'port1')
        address = device.ethernets[0].ipv4_addresses[0]
        self.assertEqual(address.address, '10.1.1.2')
        # The next hop is the router across the link, not the destination host.
        self.assertEqual(address.gateway, '10.1.1.1')

    def test_gateway_taken_from_ipv6_link_peer(self):
        self.tgn.configure_ipv6_data_traffic(
            interface='port1', src_ip='2001:db8:1::2', dst_ip='2001:db8:2::2',
            l4_protocol='udp', transmit_mode='continuous', pps=100)
        address = self.tgn.config.devices[0].ethernets[0].ipv6_addresses[0]
        self.assertEqual(address.gateway, '2001:db8:1::1')

    def test_gateway_explicit_keyword_wins(self):
        self.add_flow(gateway='10.1.1.254')
        address = self.tgn.config.devices[0].ethernets[0].ipv4_addresses[0]
        self.assertEqual(address.gateway, '10.1.1.254')

    def test_gateway_falls_back_to_connected_destination(self):
        # otg1 has no topology, so only the same-subnet rule can apply.
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg1
        tgn = dev.instantiate(via='tgn', alias='tgn')
        tgn.connect()
        try:
            tgn.configure_ipv4_data_traffic(
                interface='port1', src_ip='10.9.9.2', dst_ip='10.9.9.3',
                l4_protocol='udp', transmit_mode='continuous', pps=100)
            address = tgn.config.devices[0].ethernets[0].ipv4_addresses[0]
            self.assertEqual(address.gateway, '10.9.9.3')
        finally:
            tgn.disconnect()

    def test_destination_mac_left_on_otg_auto_default(self):
        flow = self.flow(self.add_flow())
        self.assertEqual(flow.packet[0].dst.choice, 'auto')
        self.assertEqual(flow.packet[0].src.choice, 'value')

    def test_explicit_destination_mac_overrides_auto(self):
        flow = self.flow(self.add_flow(dst_mac='00:aa:bb:cc:dd:ee'))
        self.assertEqual(flow.packet[0].dst.choice, 'value')
        self.assertEqual(flow.packet[0].dst.value, '00:aa:bb:cc:dd:ee')

    def test_emulated_device_reused_for_same_address(self):
        self.add_flow()
        self.add_flow()
        # One emulated endpoint per port, reused by the second identical flow.
        self.assertEqual(len(self.tgn.config.devices), 2)

    def test_transmit_modes(self):
        single = self.flow(self.add_flow(transmit_mode='single_burst',
                                         pkts_per_burst=17))
        self.assertEqual(single.duration.choice, 'fixed_packets')
        self.assertEqual(single.duration.fixed_packets.packets, 17)

        multi = self.flow(self.add_flow(transmit_mode='multi_burst',
                                        pkts_per_burst=5))
        self.assertEqual(multi.duration.choice, 'burst')
        self.assertEqual(multi.duration.burst.packets, 5)

        continuous = self.flow(self.add_flow(transmit_mode='continuous', gap=24))
        self.assertEqual(continuous.duration.choice, 'continuous')
        self.assertEqual(continuous.duration.continuous.gap, 24)

    def test_invalid_transmit_mode_rejected(self):
        with self.assertRaises(GenieTgnError):
            self.add_flow(transmit_mode='warp_speed')

    def test_invalid_l4_protocol_rejected(self):
        with self.assertRaises(GenieTgnError):
            self.add_flow(l4_protocol='sctp')

    def test_payload_encoded_as_custom_header(self):
        flow = self.flow(self.add_flow(payload='genie'))
        self.assertEqual(flow.packet[-1].bytes, b'genie'.hex())

    def test_dhcpv4_request_builds_rfc2131_payload(self):
        name = self.tgn.configure_dhcpv4_request(
            interface='port1', mac_src='00:11:22:33:44:55',
            requested_ip='10.1.1.50', xid=0x1234)
        flow = self.flow(name)
        self.assertEqual([type(h).__name__ for h in flow.packet],
                         ['EthernetHeader', 'Ipv4Header', 'UdpHeader',
                          'CustomHeader'])
        self.assertEqual(flow.packet[2].src_port.value, 68)
        self.assertEqual(flow.packet[2].dst_port.value, 67)

        payload = bytes.fromhex(flow.packet[-1].bytes)
        self.assertGreaterEqual(len(payload), 300)
        self.assertEqual(payload[0], 1)                       # BOOTREQUEST
        self.assertEqual(payload[4:8], (0x1234).to_bytes(4, 'big'))
        self.assertEqual(payload[236:240], bytes([99, 130, 83, 99]))
        self.assertEqual(payload[240:243], bytes([53, 1, 3]))  # DHCPREQUEST
        self.assertEqual(payload[243:249], bytes([50, 4, 10, 1, 1, 50]))

    def test_dhcpv4_request_rejects_bad_mac(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.configure_dhcpv4_request(
                interface='port1', mac_src='not-a-mac', requested_ip='10.1.1.50')

    def test_send_arp_request_emits_raw_arp_flow(self):
        name = self.tgn.send_arp_request(
            interface='port1', mac_src='00:11:22:33:44:55',
            ip_src='10.1.1.2', ip_target='10.1.1.1', count=3)
        flow = self.flow(name)
        self.assertEqual(flow.packet[0].ether_type.value, 0x0806)
        self.assertEqual(flow.packet[1].operation.value, 1)
        self.assertEqual(flow.packet[1].dst_protocol_addr.value, '10.1.1.1')
        self.assertEqual(flow.duration.fixed_packets.packets, 3)
        self.assertFalse(flow.metrics.enable)

    def test_send_arp_synthesizes_devices_when_none_exist(self):
        self.assertTrue(self.tgn.send_arp())
        self.assertEqual(len(self.tgn.config.devices), 2)
        arp_table = self.tgn.engine.get_arp_table(
            self.tgn.config.devices[0].name)
        self.assertIn('192.0.2.1', arp_table)

    def test_send_ns_synthesizes_ipv6_devices(self):
        self.assertTrue(self.tgn.send_ns(wait_time=0))
        address = self.tgn.config.devices[0].ethernets[0].ipv6_addresses[0]
        self.assertEqual(address.address, '2001:db8::2')

    def test_port_mac_is_deterministic(self):
        engine = self.tgn.translation_engine
        self.assertEqual(engine._get_port_mac('port1'),
                         engine._get_port_mac('port1'))
        self.assertNotEqual(engine._get_port_mac('port1'),
                            engine._get_port_mac('port2'))


class TestNativeDeclarativeMode(OtgTestCase):

    def build_config(self):
        config = self.tgn.new_config()
        config.ports.add(name='p1', location='localhost:5555')
        config.ports.add(name='p2', location='localhost:5556')
        flow = config.flows.add(name='f1')
        flow.tx_rx.port.tx_name = 'p1'
        flow.tx_rx.port.rx_name = 'p2'
        flow.packet.ethernet()
        flow.packet.ipv4()[-1].src.value = '10.0.0.1'
        flow.rate.pps = 500
        flow.duration.fixed_packets.packets = 100
        flow.duration.choice = 'fixed_packets'
        flow.metrics.enable = True
        return config

    def test_set_config_with_object(self):
        config = self.build_config()
        self.assertTrue(self.tgn.set_config(config))
        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])

    def test_set_config_with_json_string(self):
        payload = self.build_config().serialize()
        self.assertTrue(self.tgn.set_config(payload))
        self.assertEqual([p.name for p in self.tgn.config.ports], ['p1', 'p2'])
        self.assertEqual(self.tgn.config.flows[0].rate.pps, 500)

    def test_set_config_with_yaml_string(self):
        payload = self.build_config().serialize(encoding='yaml')
        self.assertTrue(self.tgn.set_config(payload))
        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])

    def test_set_config_with_dict(self):
        payload = json.loads(self.build_config().serialize())
        self.assertTrue(self.tgn.set_config(payload))
        self.assertEqual(self.tgn.config.flows[0].duration.choice,
                         'fixed_packets')

    def test_round_trip_preserves_packet_headers(self):
        self.tgn.set_config(self.build_config().serialize())
        flow = self.tgn.config.flows[0]
        self.assertEqual([type(h).__name__ for h in flow.packet],
                         ['EthernetHeader', 'Ipv4Header'])
        self.assertEqual(flow.packet[1].src.value, '10.0.0.1')

    def test_set_config_rejects_garbage(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.set_config('- just\n- a\n- list\n')

    def test_native_control_state_and_metrics(self):
        self.tgn.set_config(self.build_config())

        state = self.tgn.api.control_state()
        state.choice = state.TRAFFIC
        state.traffic.choice = state.traffic.FLOW_TRANSMIT
        state.traffic.flow_transmit.state = state.traffic.flow_transmit.START
        self.tgn.set_state(state)

        request = self.tgn.api.metrics_request()
        request.choice = request.FLOW
        metrics = self.tgn.get_metrics(request)
        self.assertEqual(metrics.flow_metrics[0].name, 'f1')
        self.assertEqual(metrics.flow_metrics[0].frames_tx, 100)

    def test_get_states_unsupported_in_mock_mode(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.get_states(object())

    def test_new_config_resets_stream_tracking(self):
        self.tgn.set_config(self.build_config())
        self.tgn.new_config()
        self.assertEqual(self.tgn.get_traffic_stream_names(), [])


class TestTrafficControl(OtgTestCase):

    device_name = 'otg2'

    def test_start_and_stop_traffic(self):
        name = self.add_flow()
        self.assertTrue(self.tgn.start_traffic())
        self.assertTrue(self.tgn.stop_traffic(max_time=10))
        stats = self.tgn.get_stats(view='Flow Statistics')
        self.assertGreater(stats[name]['Tx Frames'], 0)

    def test_start_traffic_targets_named_streams(self):
        first = self.add_flow()
        second = self.add_flow(interface='port2', src_ip='10.1.2.2',
                               dst_ip='10.1.1.2')
        self.tgn.start_traffic(traffic_streams=[first])
        time.sleep(0.2)
        stats = self.tgn.get_stats(view='Flow Statistics')
        self.assertGreater(stats[first]['Tx Frames'], 0)
        self.assertEqual(stats[second]['Tx Frames'], 0)

    def test_clear_traffic_removes_streams(self):
        self.add_flow()
        self.assertTrue(self.tgn.clear_traffic())
        self.assertEqual(self.tgn.get_traffic_stream_names(), [])
        self.assertEqual(self.tgn.get_stats(view='Flow Statistics'), {})

    def test_clear_statistics_baselines_counters(self):
        name = self.add_flow(transmit_mode='single_burst', pkts_per_burst=100)
        self.tgn.start_traffic()
        self.assertEqual(
            self.tgn.get_stats(view='Flow Statistics')[name]['Tx Frames'], 100)

        self.tgn.clear_statistics()
        self.assertEqual(
            self.tgn.get_stats(view='Flow Statistics')[name]['Tx Frames'], 0)

        self.tgn.start_traffic()
        self.assertEqual(
            self.tgn.get_stats(view='Flow Statistics')[name]['Tx Frames'], 100)

    def test_get_stats_rejects_unknown_view(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.get_stats(view='Nonsense Statistics')

    def test_port_statistics_are_the_default_view(self):
        self.add_flow(transmit_mode='single_burst', pkts_per_burst=100)
        self.tgn.start_traffic()

        stats = self.tgn.get_stats()
        self.assertIn('port1', stats)
        self.assertEqual(stats['port1']['Frames Tx'], 100)
        self.assertEqual(stats['port2']['Frames Rx'], 100)
        self.assertEqual(stats['port1']['Link'], 'up')

    def test_port_statistics_respect_cleared_counters(self):
        self.add_flow(transmit_mode='single_burst', pkts_per_burst=100)
        self.tgn.start_traffic()
        self.tgn.clear_statistics()
        self.assertEqual(self.tgn.get_stats()['port1']['Frames Tx'], 0)

    def test_port_statistics_surface_link_state(self):
        self.add_flow(transmit_mode='single_burst', pkts_per_burst=100)
        self.tgn.start_traffic()
        self.tgn.engine.set_port_link('port2', 'down')
        self.assertEqual(self.tgn.get_stats()['port2']['Link'], 'down')

    def test_rates_are_compared_with_each_other_when_none_is_configured(self):
        """With no configured rate there is nothing to measure against, so the
        two directions are compared with one another instead."""
        engine = self.tgn.translation_engine
        metric = SimpleNamespace(name='f', transmit='started')

        self.assertEqual(engine._check_rate(metric, 0, 100.0, 99.0, 5), [])

        breach = engine._check_rate(metric, 0, 100.0, 80.0, 5)
        self.assertTrue(any('rate diff' in entry for entry in breach), breach)

    def test_stop_does_not_wait_on_a_flow_that_never_sent(self):
        """Some backends read transmit state off the counters and call any
        flow with no frames 'started', which would never settle."""
        engine = self.tgn.translation_engine
        never_sent = SimpleNamespace(name='idle', transmit='started',
                                     frames_tx=0)
        self.assertEqual(engine._still_transmitting([never_sent]), [])

    def test_stop_waits_on_a_flow_that_is_sending(self):
        engine = self.tgn.translation_engine
        sending = SimpleNamespace(name='busy', transmit='started',
                                  frames_tx=1000)
        self.assertEqual(engine._still_transmitting([sending]), ['busy'])

    def test_stop_ignores_flows_outside_the_requested_set(self):
        engine = self.tgn.translation_engine
        sending = SimpleNamespace(name='busy', transmit='started',
                                  frames_tx=1000)
        self.assertEqual(engine._still_transmitting([sending], ['other']), [])

    def test_absent_counter_is_reported_once(self):
        """The backend warns per flow per read about a counter it never has."""
        from genie.trafficgen.otg.implementation import AbsentCounterFilter

        def record(text):
            return logging.LogRecord('snappi_ixnetwork.trafficitem',
                                     logging.WARNING, __file__, 0, text,
                                     None, None)

        noise = AbsentCounterFilter()
        first = record("Could not set result value for column 'bytes_tx': ")
        self.assertTrue(noise.filter(first))
        self.assertIn('does not report', first.getMessage())

        repeat = record("Could not set result value for column 'bytes_tx': ")
        self.assertFalse(noise.filter(repeat))

        # A different counter is still worth hearing about once.
        other = record("Could not set result value for column 'bytes_rx': ")
        self.assertTrue(noise.filter(other))

    def test_unrelated_backend_logs_are_untouched(self):
        from genie.trafficgen.otg.implementation import AbsentCounterFilter

        message = 'Flows generate/apply took 3s'
        keep = logging.LogRecord('snappi_ixnetwork.trafficitem',
                                 logging.WARNING, __file__, 0, message,
                                 None, None)
        self.assertTrue(AbsentCounterFilter().filter(keep))
        self.assertEqual(keep.getMessage(), message)


class TestTrafficLossVerification(OtgTestCase):

    device_name = 'otg2'

    def start_burst(self, packets=1000, pps=1000):
        name = self.add_flow(transmit_mode='single_burst',
                             pkts_per_burst=packets, pps=pps)
        return name

    def test_clean_run_reports_no_loss(self):
        name = self.start_burst()
        self.tgn.start_traffic()
        data = self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=1)
        row = data[0]['stream'][name]
        self.assertEqual(row['Tx Frames'], 1000)
        self.assertEqual(row['Rx Frames'], 1000)
        self.assertEqual(row['Loss %'], 0.0)
        self.assertEqual(row['Outage (seconds)'], 0.0)

    def test_loss_beyond_tolerance_raises(self):
        name = self.start_burst()
        self.tgn.engine.set_flow_loss(name, loss_pct=10.0)
        self.tgn.start_traffic()
        with self.assertRaises(GenieTgnError) as ctx:
            self.tgn.check_traffic_loss(loss_tolerance=1, check_iteration=1,
                                        rate_tolerance=None)
        self.assertIn(name, str(ctx.exception))

    def test_zero_check_iteration_is_rejected(self):
        """check_iteration=0 must not report a silent, unverified pass."""
        self.start_burst()
        self.tgn.start_traffic()
        with self.assertRaises(GenieTgnError) as ctx:
            self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=0)
        self.assertIn('check_iteration', str(ctx.exception))

    def test_negative_check_iteration_is_rejected(self):
        """A negative check_iteration is likewise a misconfiguration."""
        self.start_burst()
        self.tgn.start_traffic()
        with self.assertRaises(GenieTgnError) as ctx:
            self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=-3)
        self.assertIn('check_iteration', str(ctx.exception))

    def test_finished_burst_is_not_reported_as_dead(self):
        """A burst that completed before baselining legitimately reads tx=0."""
        name = self.start_burst()
        self.tgn.start_traffic()
        # Baseline after the burst drained, so its counters read zero from here.
        self.tgn.clear_statistics()

        data = self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=1,
                                           rate_tolerance=None)
        row = data[0]['stream'][name]
        self.assertEqual(row['Tx Frames'], 0)
        self.assertEqual(row['State'], 'stopped')

    def _score_silent_flow(self, name, transmit):
        """Score a synthetic zero-transmit metric for a configured flow."""
        metric = SimpleNamespace(name=name, frames_tx=0, frames_rx=0,
                                 frames_tx_rate=0.0, frames_rx_rate=0.0,
                                 transmit=transmit)
        return self.tgn.translation_engine._evaluate_flow(
            metric, None, 0, None, {})

    def test_a_stopped_flow_with_a_residual_rate_is_not_a_deviation(self):
        """Rates are sampled over a window, so a stopped flow can report a
        small leftover rather than a clean zero."""
        name = self.add_flow(transmit_mode='continuous', pps=1000)
        metric = SimpleNamespace(name=name, frames_tx=0, frames_rx=0,
                                 frames_tx_rate=0.004, frames_rx_rate=0.0,
                                 transmit='stopped')
        _, failures = self.tgn.translation_engine._evaluate_flow(
            metric, None, 100, 5, {})
        self.assertEqual(failures, [])

    def test_a_started_flow_sending_nothing_still_fails(self):
        """The zero transmit guard has to survive the finished-burst fix."""
        name = self.add_flow(transmit_mode='continuous', pps=1000)
        _, failures = self._score_silent_flow(name, 'started')
        self.assertTrue(any('no traffic transmitted' in f for f in failures),
                        'a flow that claims to be transmitting but sends '
                        'nothing must still be reported: %s' % failures)

    def test_a_stopped_flow_sending_nothing_is_not_a_failure(self):
        name = self.add_flow(transmit_mode='continuous', pps=1000)
        _, failures = self._score_silent_flow(name, 'stopped')
        self.assertEqual(failures, [])

    def test_byte_rates_are_reported(self):
        """The byte rate fields are named by the OTG schema, not invented.

        The schema calls these tx_rate_bytes and rx_rate_bytes; reading
        bytes_tx_rate instead silently yields zero against a real controller.
        """
        name = self.start_burst()
        self.tgn.start_traffic()
        data = self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=1,
                                           rate_tolerance=None)
        row = data[0]['stream'][name]
        self.assertGreater(row['Tx Rate (Bps)'], 0)
        self.assertGreater(row['Rx Rate (Bps)'], 0)

    def test_loss_within_tolerance_passes(self):
        name = self.start_burst()
        self.tgn.engine.set_flow_loss(name, loss_pct=2.0)
        self.tgn.start_traffic()
        data = self.tgn.check_traffic_loss(loss_tolerance=5, check_iteration=1,
                                           rate_tolerance=None)
        self.assertAlmostEqual(data[0]['stream'][name]['Loss %'], 2.0, places=2)

    def test_raise_on_loss_false_returns_data(self):
        name = self.start_burst()
        self.tgn.engine.set_flow_loss(name, loss_pct=50.0)
        self.tgn.start_traffic()
        data = self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=1,
                                           rate_tolerance=None,
                                           raise_on_loss=False)
        self.assertAlmostEqual(data[0]['stream'][name]['Loss %'], 50.0, places=2)

    def test_outage_exceeding_max_outage_raises(self):
        name = self.start_burst(packets=1000, pps=100)
        self.tgn.engine.set_flow_loss(name, loss_frames=500)
        self.tgn.start_traffic()
        with self.assertRaises(GenieTgnError) as ctx:
            self.tgn.check_traffic_loss(loss_tolerance=100, max_outage=1,
                                        check_iteration=1, rate_tolerance=None)
        self.assertIn('outage', str(ctx.exception))

    def test_link_down_is_reported_as_total_loss(self):
        name = self.start_burst()
        self.tgn.engine.set_port_link('port2', 'down')
        self.tgn.start_traffic()
        data = self.tgn.check_traffic_loss(loss_tolerance=100,
                                           rate_tolerance=None,
                                           check_iteration=1)
        self.assertEqual(data[0]['stream'][name]['Rx Frames'], 0)
        self.assertEqual(data[0]['stream'][name]['Loss %'], 100.0)

    def test_counter_reset_does_not_produce_negative_delta(self):
        name = self.start_burst()
        self.tgn.start_traffic()
        self.tgn.clear_statistics()

        # Chassis reboot: counters drop below the recorded baseline.
        self.tgn.engine.reset_counters()

        data = self.tgn.check_traffic_loss(loss_tolerance=0, check_iteration=1,
                                           rate_tolerance=None,
                                           raise_on_loss=False)
        row = data[0]['stream'][name]
        self.assertEqual(row['Tx Frames'], 0)
        self.assertEqual(row['Frames Delta'], 0)
        self.assertEqual(row['Loss %'], 0.0)

        # The stale baseline must have been discarded, so new traffic counts.
        self.tgn.start_traffic()
        self.assertEqual(
            self.tgn.get_stats(view='Flow Statistics')[name]['Tx Frames'], 1000)

    def test_per_stream_tolerance_override(self):
        name = self.start_burst()
        self.tgn.engine.set_flow_loss(name, loss_pct=8.0)
        self.tgn.start_traffic()
        data = self.tgn.check_traffic_loss(
            loss_tolerance=1, check_iteration=1, rate_tolerance=None,
            outage_dict={'traffic_streams': {name: {'loss_tolerance': 20}}})
        self.assertAlmostEqual(data[0]['stream'][name]['Loss %'], 8.0, places=2)

    def test_no_configured_streams_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.check_traffic_loss()

    def test_missing_metrics_is_not_a_pass(self):
        '''A stream the controller reports nothing for must not pass silently.

        Regression: an empty metrics response produced {"stream": {}} and no
        failures, so the Genie harness reported traffic verified when nothing
        had been measured at all.
        '''
        from genie.trafficgen.otg.mock import MetricsResponse

        name = self.start_burst()
        self.tgn.start_traffic()

        with patch.object(type(self.tgn.api), 'get_metrics',
                          return_value=MetricsResponse(flow_metrics=[])):
            with self.assertRaises(GenieTgnError) as ctx:
                self.tgn.check_traffic_loss(loss_tolerance=0,
                                            rate_tolerance=None,
                                            check_iteration=1)
        self.assertIn('No traffic data found', str(ctx.exception))
        self.assertIn(name, str(ctx.exception))

    def test_partial_metrics_is_not_a_pass(self):
        '''Streams reported by the controller must cover every stream asked for.'''
        first = self.start_burst()
        second = self.add_flow(interface='port2', src_ip='10.1.2.2',
                               dst_ip='10.1.1.2', transmit_mode='single_burst',
                               pkts_per_burst=1000, pps=1000)
        self.tgn.start_traffic()

        full = self.tgn.api.get_metrics(self._flow_request())
        only_first = [m for m in full.flow_metrics if m.name == first]

        from genie.trafficgen.otg.mock import MetricsResponse
        with patch.object(type(self.tgn.api), 'get_metrics',
                          return_value=MetricsResponse(flow_metrics=only_first)):
            with self.assertRaises(GenieTgnError) as ctx:
                self.tgn.check_traffic_loss(traffic_streams=[first, second],
                                            loss_tolerance=0,
                                            rate_tolerance=None,
                                            check_iteration=1)
        self.assertIn(second, str(ctx.exception))

    def _flow_request(self):
        request = self.tgn.api.metrics_request()
        request.choice = request.FLOW
        return request

    def test_statistics_table_is_logged(self):
        '''The harness relies on the logged table as the evidence of a check.'''
        name = self.start_burst()
        self.tgn.start_traffic()

        with self.assertLogs('genie.trafficgen.otg.translation',
                             level='INFO') as captured:
            self.tgn.check_traffic_loss(loss_tolerance=0, rate_tolerance=None,
                                        check_iteration=1)

        output = '\n'.join(captured.output)
        self.assertIn('Configured traffic streams', output)
        self.assertIn('Traffic statistics, check 1/1', output)
        for column in ('Traffic Item', 'Tx Frames', 'Rx Frames', 'Loss %',
                       'Outage (seconds)'):
            self.assertIn(column, output)
        self.assertIn(name, output)

    def _breach_levels(self, **kwargs):
        '''Runs a lossy check and returns the log levels of the breach lines.'''
        name = self.start_burst()
        self.tgn.engine.set_flow_loss(name, loss_pct=50.0)
        self.tgn.start_traffic()

        with self.assertLogs('genie.trafficgen.otg.translation',
                             level='INFO') as captured:
            try:
                self.tgn.check_traffic_loss(loss_tolerance=0,
                                            rate_tolerance=None, **kwargs)
            except GenieTgnError:
                pass
        return [record.levelname for record in captured.records
                if record.getMessage().startswith('* ')]

    def test_breach_is_logged_as_error_when_it_fails_the_check(self):
        levels = self._breach_levels(check_iteration=1, raise_on_loss=True)
        self.assertTrue(levels)
        self.assertEqual(set(levels), {'ERROR'})

    def test_breach_is_not_logged_as_error_when_not_enforced(self):
        '''raise_on_loss=False means the caller is measuring, not enforcing.

        Regression: induced loss was logged at ERROR inside a passing step,
        making a correct result look like a failure.
        '''
        levels = self._breach_levels(check_iteration=1, raise_on_loss=False)
        self.assertTrue(levels)
        self.assertNotIn('ERROR', levels)

    def test_breach_is_not_logged_as_error_while_retries_remain(self):
        '''Traffic may still converge, so an early breach is not yet a failure.'''
        levels = self._breach_levels(check_iteration=2, check_interval=0,
                                     raise_on_loss=True)
        # The last iteration still fails, so only its breaches are errors.
        self.assertIn('INFO', levels)
        self.assertIn('ERROR', levels)

    def test_counter_reset_at_start_is_detected(self):
        '''A backend that zeroes counters on start must not look idle.

        Regression for IxNetwork: it resets a flow's counters each time
        traffic starts, so a baseline taken by clear_statistics is stale and
        the run appeared to transmit nothing.
        '''
        name = self.add_flow(transmit_mode='single_burst',
                             pkts_per_burst=1000, pps=2000)
        self.tgn.engine.set_counter_reset_on_start(True)

        # First run completes, leaving the counters at 1000.
        self.tgn.start_traffic()
        time.sleep(0.8)
        self.tgn.stop_traffic(max_time=10)
        self.tgn.clear_statistics()

        # Counters restart here, below the baseline just recorded.
        self.tgn.start_traffic()
        time.sleep(0.8)

        transmitted = self.tgn.get_stats(view='Flow Statistics')[name]['Tx Frames']
        self.assertGreater(transmitted, 0)

    def test_baseline_is_clamped_to_a_restarted_counter(self):
        engine = self.tgn.translation_engine
        baseline = {'frames_tx': 10000, 'frames_rx': 10000,
                    'bytes_tx': 1280000, 'bytes_rx': 1280000}
        engine._clamp(baseline, SimpleNamespace(
            name='f', frames_tx=12, frames_rx=10, bytes_tx=1536, bytes_rx=1280))
        self.assertEqual(baseline['frames_tx'], 12)
        self.assertEqual(baseline['frames_rx'], 10)

    def test_baseline_kept_for_monotonic_counters(self):
        engine = self.tgn.translation_engine
        baseline = {'frames_tx': 100, 'frames_rx': 100,
                    'bytes_tx': 128, 'bytes_rx': 128}
        engine._clamp(baseline, SimpleNamespace(
            name='f', frames_tx=500, frames_rx=500, bytes_tx=640, bytes_rx=640))
        self.assertEqual(baseline['frames_tx'], 100)
        self.assertEqual(baseline['frames_rx'], 100)

    def test_duplicate_streams_rejected(self):
        name = self.start_burst()
        with self.assertRaises(GenieTgnError) as ctx:
            self.tgn.check_traffic_loss(traffic_streams=[name, name])
        self.assertIn('Duplicate', str(ctx.exception))

    def test_rate_deviation_detected(self):
        name = self.add_flow(transmit_mode='continuous', pps=1000)
        self.tgn.engine.set_flow_loss(name, loss_pct=40.0)
        self.tgn.start_traffic()
        time.sleep(0.2)
        with self.assertRaises(GenieTgnError) as ctx:
            self.tgn.check_traffic_loss(loss_tolerance=100, max_outage=None,
                                        rate_tolerance=5, check_iteration=1)
        self.assertIn('rate deviation', str(ctx.exception))


class TestHarnessCompatibility(OtgTestCase):
    '''Covers the TrafficGen surface that genie.harness drives.'''

    device_name = 'otg2'

    def test_load_and_remove_configuration(self):
        config = self.tgn.new_config()
        config.ports.add(name='p1', location='localhost:5555')
        config.flows.add(name='f1').tx_rx.port.tx_name = 'p1'
        path = os.path.join(os.path.dirname(__file__), 'otg_config_tmp.json')
        with open(path, 'w') as config_file:
            config_file.write(config.serialize())
        try:
            self.assertTrue(self.tgn.load_configuration(path, wait_time=0))
            self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])
        finally:
            os.remove(path)

        self.assertTrue(self.tgn.remove_configuration(wait_time=0))
        self.assertEqual(self.tgn.get_traffic_stream_names(), [])

    def test_load_configuration_missing_file(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.load_configuration('/nonexistent/otg.json', wait_time=0)

    def test_assign_ixia_ports_is_a_no_op(self):
        self.assertTrue(self.tgn.assign_ixia_ports(wait_time=0))

    def test_apply_traffic_commits_configuration(self):
        name = self.add_flow()
        self.assertTrue(self.tgn.apply_traffic(wait_time=0))
        self.assertIn(name, [f.name for f in self.tgn.api.get_config().flows])

    def test_protocol_start_and_stop(self):
        self.add_flow()
        self.assertTrue(self.tgn.start_all_protocols(wait_time=0))
        self.assertTrue(self.tgn.stop_all_protocols(wait_time=0))

    def test_generate_traffic_streams(self):
        name = self.add_flow()
        self.assertTrue(self.tgn.generate_traffic_streams(
            traffic_streams=[name], wait_time=0))

    def test_generate_unknown_traffic_stream_raises(self):
        self.add_flow()
        with self.assertRaises(GenieTgnError):
            self.tgn.generate_traffic_streams(traffic_streams=['nope'],
                                              wait_time=0)

    def test_create_genie_statistics_view_enables_metrics(self):
        name = self.add_flow()
        self.flow(name).metrics.enable = False
        self.assertTrue(self.tgn.create_genie_statistics_view())
        self.assertTrue(self.flow(name).metrics.enable)

    def test_packet_rate_sampling(self):
        name = self.add_flow(pps=1000)
        self.tgn.start_traffic()
        time.sleep(0.2)
        self.assertEqual(self.tgn.get_current_packet_rate(first_sample=True),
                         {name: 1000.0})
        self.assertEqual(self.tgn.get_reference_packet_rate(), {name: 1000.0})

    def test_traffic_streams_table_and_golden_profile(self):
        name = self.add_flow(transmit_mode='single_burst', pkts_per_burst=500)
        self.tgn.start_traffic()

        table = self.tgn.create_traffic_streams_table(set_golden=True)
        self.assertEqual(table.field_names[:2],
                         ['Source/Dest Port Pair', 'Traffic Item'])
        self.assertEqual(len(table.rows), 1)
        self.assertEqual(table.rows[0][0], 'port1 - port2')
        self.assertEqual(table.rows[0][1], name)
        self.assertEqual(table.rows[0][2], 500)

        golden = self.tgn.get_golden_profile()
        self.assertEqual(golden.rows, table.rows)

    def test_compare_identical_profiles_passes(self):
        self.add_flow(transmit_mode='single_burst', pkts_per_burst=500)
        self.tgn.start_traffic()
        profile = self.tgn.create_traffic_streams_table()
        self.assertTrue(self.tgn.compare_traffic_profile(profile, profile))

    def test_compare_profiles_detects_loss_difference(self):
        name = self.add_flow(transmit_mode='single_burst', pkts_per_burst=500)
        self.tgn.start_traffic()
        golden = self.tgn.create_traffic_streams_table()

        self.tgn.clear_statistics()
        self.tgn.engine.set_flow_loss(name, loss_pct=50.0)
        self.tgn.start_traffic()
        degraded = self.tgn.create_traffic_streams_table()

        with self.assertRaises(GenieTgnError):
            self.tgn.compare_traffic_profile(golden, degraded,
                                             loss_tolerance=1, rate_tolerance=1)

    def test_compare_profiles_rejects_mismatched_items(self):
        self.add_flow(transmit_mode='single_burst', pkts_per_burst=500)
        self.tgn.start_traffic()
        profile = self.tgn.create_traffic_streams_table()

        self.add_flow(interface='port2', src_ip='10.1.2.2', dst_ip='10.1.1.2',
                      transmit_mode='single_burst', pkts_per_burst=500)
        self.tgn.start_traffic()
        wider = self.tgn.create_traffic_streams_table()

        with self.assertRaises(GenieTgnError):
            self.tgn.compare_traffic_profile(profile, wider)

    def test_compare_profiles_rejects_bad_input(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.compare_traffic_profile('not-a-table', 'not-a-table')

    def test_profile_round_trips_through_harness_helpers(self):
        import genie.harness.commons  # noqa: F401  breaks a genie circular import
        from genie.utils.profile import pickle_traffic, unpickle_traffic

        self.add_flow(transmit_mode='single_burst', pkts_per_burst=500)
        self.tgn.start_traffic()
        profile = self.tgn.create_traffic_streams_table()

        directory = tempfile.mkdtemp()
        try:
            path = pickle_traffic(profile, location=directory,
                                  tgn_profile_name='golden_traffic_profile')
            restored = unpickle_traffic(path)
        finally:
            shutil.rmtree(directory)

        self.assertEqual(restored.field_names, profile.field_names)
        self.assertTrue(self.tgn.compare_traffic_profile(profile, restored))

    def test_golden_profile_defaults_to_empty_table(self):
        self.assertEqual(self.tgn.get_golden_profile().field_names, [])


class TestConfigurationArchiving(OtgTestCase):
    '''A loaded configuration is kept alongside the rest of the run artifacts.'''

    device_name = 'otg2'
    archived_name = 'otg2_otg_source_config.json'

    def setUp(self):
        super().setUp()
        self.workspace = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

        config = self.tgn.new_config()
        config.ports.add(name='p1', location='localhost:5555')
        config.flows.add(name='f1').tx_rx.port.tx_name = 'p1'
        self.contents = config.serialize()

        self.source = os.path.join(self.workspace, 'otg_source_config.json')
        with open(self.source, 'w') as handle:
            handle.write(self.contents)

    def run_directory(self):
        directory = os.path.join(self.workspace, 'runinfo')
        os.mkdir(directory)
        return directory

    @staticmethod
    def easypy(directory):
        '''Stands in for the runtime, which only has a runinfo inside a job.'''
        return SimpleNamespace(runinfo=object(), directory=directory)

    def test_configuration_is_archived(self):
        directory = self.run_directory()
        with patch.object(implementation, 'runtime', self.easypy(directory)):
            self.tgn.load_configuration(self.source, wait_time=0)

        self.assertEqual(os.listdir(directory), [self.archived_name])
        with open(os.path.join(directory, self.archived_name)) as handle:
            self.assertEqual(handle.read(), self.contents)

    def test_archived_name_is_scoped_to_the_device(self):
        directory = self.run_directory()
        with patch.object(implementation, 'runtime', self.easypy(directory)):
            self.tgn.load_configuration(self.source, wait_time=0)

        # Two traffic generators loading the same file must not collide.
        self.assertTrue(os.listdir(directory)[0].startswith(self.device_name))

    def test_nothing_is_written_outside_easypy(self):
        directory = self.run_directory()
        standalone = SimpleNamespace(runinfo=None, directory=directory)
        with patch.object(implementation, 'runtime', standalone):
            self.tgn.load_configuration(self.source, wait_time=0)

        self.assertEqual(os.listdir(directory), [])

    def test_a_failed_archive_does_not_fail_the_load(self):
        unwritable = os.path.join(self.workspace, 'no-such-directory')
        with patch.object(implementation, 'runtime', self.easypy(unwritable)):
            self.assertTrue(
                self.tgn.load_configuration(self.source, wait_time=0))

        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])

    def test_configuration_is_archived_even_when_the_push_fails(self):
        directory = self.run_directory()
        with patch.object(implementation, 'runtime', self.easypy(directory)), \
                patch.object(self.tgn, 'set_config',
                             side_effect=GenieTgnError('rejected')):
            with self.assertRaises(GenieTgnError):
                self.tgn.load_configuration(self.source, wait_time=0)

        # The configuration the controller rejected is the one worth keeping.
        self.assertEqual(os.listdir(directory), [self.archived_name])


if __name__ == '__main__':
    unittest.main()
