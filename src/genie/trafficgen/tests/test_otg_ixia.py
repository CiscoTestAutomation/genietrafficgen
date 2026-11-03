'''Backward compatibility of the OTG plugin with the IxiaNative one.

A testbed moving from ``os: ixianative`` to ``os: otg`` plus
``platform: ixia`` keeps its scripts, so these tests hold the two APIs
together: every public IxiaNative method is answerable, the portable ones
do the right thing against the mock transport, and the rest say which
IxNetwork construct they are and what to use instead.
'''

import ast
import os
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyats.topology import loader

from genie.harness.exceptions import GenieTgnError
from genie.trafficgen.ixianative.implementation import IxiaNative
from genie.trafficgen.ixiarestpy.implementation import IxiaRestPy
from genie.trafficgen.otg.implementation import Otg, _count_pcap_frames
from genie.trafficgen.otg.ixia import IxiaOtg
from genie.trafficgen.otg.ixia.compat import UNSUPPORTED

TESTBED = os.path.join(os.path.dirname(__file__), 'testbed_otg.yaml')

# A decorator IxiaNative applies to its own methods, not something a
# script calls.
NOT_API = {'isconnected'}


def public_methods(cls):
    '''The method names a script can call on a plugin class.'''
    return {name for name in dir(cls)
            if not name.startswith('_') and callable(getattr(cls, name, None))}


def source_methods(path):
    '''Public methods defined in a source file, by name.

    Read from the source rather than the class so a name is counted where
    it is written, which is what the parity guard is about.
    '''
    names = set()
    for node in ast.walk(ast.parse(open(path).read())):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and not item.name.startswith('_'):
                    names.add(item.name)
    return names


class TestIxiaNativeParity(unittest.TestCase):
    '''The guard: an IxiaNative script must find every method it calls.'''

    def test_every_ixianative_method_is_answerable(self):
        expected = public_methods(IxiaNative) - NOT_API
        missing = sorted(expected - public_methods(IxiaOtg))
        self.assertEqual(missing, [], 'IxiaNative methods missing from the '
                                      'IXIA OTG plugin: {}'.format(missing))

    def test_every_ixiarestpy_method_is_answerable(self):
        missing = sorted(public_methods(IxiaRestPy) - public_methods(IxiaOtg))
        self.assertEqual(missing, [], 'IxiaRestPy methods missing from the '
                                      'IXIA OTG plugin: {}'.format(missing))

    def test_unsupported_table_covers_only_what_is_missing(self):
        '''Every entry names a method the OTG plugin does not implement.

        An entry for something now implemented would shadow a working
        method with an error, so it has to be retired.
        '''
        implemented = sorted(name for name in UNSUPPORTED
                             if hasattr(Otg, name))
        self.assertEqual(implemented, [],
                         'These are implemented on the OTG plugin and must '
                         'be removed from UNSUPPORTED: {}'.format(implemented))

    def test_unsupported_table_has_no_stale_entries(self):
        '''Every entry is a method IxiaNative actually has.'''
        source = os.path.join(os.path.dirname(__file__), '..', 'ixianative',
                              'implementation.py')
        unknown = sorted(set(UNSUPPORTED) - source_methods(source))
        self.assertEqual(unknown, [],
                         'UNSUPPORTED names methods IxiaNative does not '
                         'have: {}'.format(unknown))

    def test_portable_methods_are_shared_with_other_backends(self):
        '''The portable names live on Otg, so every backend inherits them.'''
        for name in ('start_packet_capture', 'set_packet_rate',
                     'get_packet_size', 'start_traffic_stream',
                     'check_flow_groups_loss', 'get_flow_statistics_data',
                     'save_configuration'):
            self.assertTrue(hasattr(Otg, name),
                            '{} should be on the base OTG plugin'.format(name))


class TestIxiaOtgAbstraction(unittest.TestCase):
    '''How a testbed selects the IXIA backend.'''

    @classmethod
    def setUpClass(cls):
        cls.testbed = loader.load(TESTBED)

    def test_platform_token_resolves(self):
        dev = self.testbed.devices.ixia1
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'IxiaOtg')

    def test_plain_otg_device_is_unaffected(self):
        dev = self.testbed.devices.otg2
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Otg')

    def test_extension_is_not_assumed(self):
        '''Without ext the controller speaks OTG natively, as it does for
        the public plugin; platform: ixia does not imply IxNetwork.'''
        dev = self.testbed.devices.ixia1
        dev.instantiate()
        self.assertIsNone(dev.default.ext)

    def test_connection_names_the_extension(self):
        dev = self.testbed.devices.ixia2
        dev.instantiate()
        self.assertEqual(dev.default.ext, 'ixnetwork')

    def test_connection_defaults_are_the_public_plugin_ones(self):
        '''A testbed that already sets platform: ixia connects as before.'''
        for name in ('DEFAULT_TRANSPORT', 'SUPPORTED_TRANSPORTS',
                     'USES_TEST_PORTS'):
            self.assertEqual(getattr(IxiaOtg, name), getattr(Otg, name),
                             name)


class FlowMixin:
    '''Streams configured the way a migrated IxiaNative script does.

    Kept out of the TestCase below, which holds only the fixtures, so these
    helpers belong to the test cases that call them. They use the self.tgn
    that IxiaOtgTestCase connects.
    '''

    def add_flow(self, interface='port1', src_ip='192.0.2.2',
                 dst_ip='198.51.100.2', **kwargs):
        '''Configure a stream on the given port.'''
        kwargs.setdefault('l4_protocol', 'udp')
        kwargs.setdefault('transmit_mode', 'continuous')
        kwargs.setdefault('pps', 1000)
        return self.tgn.configure_ipv4_data_traffic(
            interface=interface, src_ip=src_ip, dst_ip=dst_ip, **kwargs)

    def second_flow(self):
        '''Configure a stream in the opposite direction, from port2.'''
        return self.add_flow(interface='port2', src_ip='198.51.100.2',
                             dst_ip='192.0.2.2')


class IxiaOtgTestCase(FlowMixin, unittest.TestCase):
    '''Connects a mock-transport IXIA OTG device for each test.'''

    @classmethod
    def setUpClass(cls):
        cls.testbed = loader.load(TESTBED)

    def setUp(self):
        self.dev = self.testbed.devices.ixia1
        self.tgn = self.dev.instantiate(via='tgn', alias='tgn')
        self.tgn.connect()

    def tearDown(self):
        self.tgn.disconnect()
        self.dev.destroy()


class TestUnsupportedMethods(IxiaOtgTestCase):
    '''What an IxNetwork-only call reports.'''

    def test_every_unsupported_method_raises_with_its_reason(self):
        for name, reason in UNSUPPORTED.items():
            with self.subTest(method=name):
                with self.assertRaises(GenieTgnError) as caught:
                    getattr(self.tgn, name)()
                message = str(caught.exception)
                self.assertIn(name, message)
                self.assertIn(reason, message)

    def test_reason_points_at_an_alternative(self):
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.get_vports()
        self.assertIn('get_stats', str(caught.exception))


class TestCaptureCompatibility(IxiaOtgTestCase):
    '''The IxiaNative packet capture calls, on the OTG capture model.'''

    def setUp(self):
        super().setUp()
        self.add_flow()
        self.second_flow()
        self.tgn.apply_traffic(wait_time=0)

    def captured_ports(self):
        return {name for capture in self.tgn.config.captures
                for name in capture.port_names}

    def test_enable_adds_a_capture_for_each_port(self):
        self.tgn.enable_data_packet_capture('port1, port2')
        self.assertEqual(self.captured_ports(), {'port1', 'port2'})

    def test_enable_accepts_a_list(self):
        self.tgn.enable_data_packet_capture(['port1'])
        self.assertEqual(self.captured_ports(), {'port1'})

    def test_control_and_data_share_one_capture(self):
        '''OTG captures a port, without IxNetwork's hardware/software split.'''
        self.tgn.enable_data_packet_capture('port1')
        self.tgn.enable_control_packet_capture('port1')
        self.assertEqual(len(self.tgn.config.captures), 1)

    def test_disable_removes_the_port(self):
        self.tgn.enable_data_packet_capture('port1, port2')
        self.tgn.disable_data_packet_capture('port1')
        self.assertEqual(self.captured_ports(), {'port2'})

    def test_disable_of_the_last_port_removes_the_capture(self):
        '''OTG refuses a capture without ports at the next push.'''
        self.tgn.enable_data_packet_capture('port1, port2')
        self.tgn.disable_data_packet_capture('port1')
        self.tgn.disable_control_packet_capture('port2')
        self.assertEqual(len(self.tgn.config.captures), 0)
        self.assertTrue(self.tgn.apply_traffic(wait_time=0))

    def test_disable_of_an_uncaptured_port_is_harmless(self):
        self.assertTrue(self.tgn.disable_control_packet_capture('port1'))

    def test_start_and_stop_report_success(self):
        self.tgn.enable_data_packet_capture('port1')
        self.tgn.apply_traffic(wait_time=0)
        self.assertTrue(self.tgn.start_packet_capture(capture_time=0))
        self.assertIn('port1', self.tgn.engine.capturing_ports())
        self.assertTrue(self.tgn.stop_packet_capture())
        self.assertNotIn('port1', self.tgn.engine.capturing_ports())

    def test_capture_count_of_an_empty_capture(self):
        self.assertEqual(self.tgn.get_packet_capture_count('port1', 'data'), 0)

    def test_capture_count_rejects_an_unknown_type(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.get_packet_capture_count('port1', 'neither')

    def test_capture_data_is_returned_as_bytes(self):
        self.assertIsInstance(self.tgn.get_packet_capture_data('port1'), bytes)

    def test_save_names_the_file_after_the_port_and_type(self):
        directory = tempfile.mkdtemp()
        path = self.tgn.save_packet_capture_file('port1', 'data', 'run',
                                                 directory=directory)
        self.assertEqual(os.path.basename(path), 'port1_HW_run.pcap')
        self.assertTrue(os.path.exists(path))

    def test_save_distinguishes_control_from_data(self):
        directory = tempfile.mkdtemp()
        path = self.tgn.save_packet_capture_file('port1', 'control', 'run',
                                                 directory=directory)
        self.assertEqual(os.path.basename(path), 'port1_SW_run.pcap')

    def test_export_copies_the_capture(self):
        directory = tempfile.mkdtemp()
        source = self.tgn.save_packet_capture_file('port1', 'data', 'run',
                                                   directory=directory)
        with patch('genie.trafficgen.otg.implementation.runtime',
                   SimpleNamespace(directory=directory)):
            exported = self.tgn.export_packet_capture_file(
                source, 'exported.pcap')
        self.assertEqual(exported, os.path.join(directory, 'exported.pcap'))
        self.assertTrue(os.path.exists(exported))
        self.assertEqual(os.path.basename(exported), 'exported.pcap')


class TestPcapFrameCounting(unittest.TestCase):
    '''Counting frames in what a controller hands back.'''

    @staticmethod
    def classic_pcap(frames, size=64):
        header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        record = struct.pack('<IIII', 0, 0, size, size) + b'\x00' * size
        return header + record * frames

    @staticmethod
    def pcapng(frames, size=64):
        section = (struct.pack('<III', 0x0a0d0d0a, 28, 0x1a2b3c4d)
                   + struct.pack('<HHq', 1, 0, -1) + struct.pack('<I', 28))
        body = struct.pack('<IIIII', 0, 0, 0, size, size) + b'\x00' * size
        total = 12 + len(body)
        packet = struct.pack('<II', 6, total) + body + struct.pack('<I', total)
        return section + packet * frames

    def count(self, data):
        return _count_pcap_frames(data)

    def test_classic_pcap(self):
        self.assertEqual(self.count(self.classic_pcap(3)), 3)

    def test_pcapng(self):
        # snappi_ixnetwork answers a pcap request with pcapng.
        self.assertEqual(self.count(self.pcapng(2)), 2)

    def test_header_without_packets(self):
        self.assertEqual(self.count(self.classic_pcap(0)), 0)

    def test_empty_capture(self):
        self.assertEqual(self.count(b''), 0)

    def test_unrecognised_container(self):
        with self.assertRaises(GenieTgnError):
            self.count(b'not a capture at all')


class TestRateAndSizeCompatibility(IxiaOtgTestCase):
    '''The IxiaNative rate and frame size calls, on the OTG flow model.'''

    def setUp(self):
        super().setUp()
        self.name = self.add_flow()
        self.tgn.apply_traffic(wait_time=0)

    def test_set_and_get_packet_rate(self):
        self.tgn.set_packet_rate(self.name, 2500, start_traffic=False)
        self.assertEqual(self.tgn.get_packet_rate(self.name), 2500)

    def test_set_line_rate_switches_the_rate_choice(self):
        # Test the portable request against a backend accepting percentage.
        # The in-memory simulator has no physical link speed to interpret it.
        with patch.object(self.tgn.api, 'update_flows'):
            self.tgn.set_line_rate(self.name, 40, start_traffic=False)
        self.assertEqual(self.tgn.get_line_rate(self.name), 40)

    def test_mock_line_rate_is_refused_without_changing_the_flow(self):
        before = self.tgn.config.serialize()
        with self.assertRaisesRegex(GenieTgnError, 'link speed'):
            self.tgn.set_line_rate(self.name, 40, start_traffic=False)
        self.assertEqual(self.tgn.config.serialize(), before)

    def test_reading_the_wrong_rate_unit_is_refused(self):
        '''A flow carries one rate choice, so asking for another is wrong.'''
        with self.assertRaises(GenieTgnError):
            self.tgn.get_line_rate(self.name)

    def test_layer2_bit_rate_in_bits(self):
        self.tgn.set_layer2_bit_rate(self.name, 100, 'Mbps',
                                     start_traffic=False)
        self.assertEqual(self.tgn.get_layer2_bit_rate(self.name), 100)

    def test_layer2_bit_rate_converts_bytes_to_bits(self):
        self.tgn.set_layer2_bit_rate(self.name, 10, 'MBps',
                                     start_traffic=False)
        self.assertEqual(self.tgn.get_layer2_bit_rate(self.name), 80)

    def test_layer2_bit_rate_rejects_an_unknown_unit(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.set_layer2_bit_rate(self.name, 10, 'furlongs',
                                         start_traffic=False)

    def test_set_and_get_packet_size(self):
        self.tgn.set_packet_size_fixed(self.name, 512, start_traffic=False)
        self.assertEqual(self.tgn.get_packet_size(self.name), 512)

    def test_live_setters_do_not_restart_a_running_flow(self):
        self.tgn.start_traffic(wait_time=0)
        with patch.object(self.tgn, 'start_traffic') as start:
            self.tgn.set_packet_rate(self.name, 2500, start_traffic_time=0)
            self.tgn.set_layer2_bit_rate(self.name, 1, 'Mbps',
                                        start_traffic_time=0)
            self.tgn.set_packet_size_fixed(self.name, 256,
                                           start_traffic_time=0)
        start.assert_not_called()
        self.assertEqual(self.tgn._flow_transmit_states()[self.name], 'started')

    def test_line_rate_does_not_restart_a_running_supporting_backend(self):
        self.tgn.start_traffic(wait_time=0)
        with patch.object(self.tgn.api, 'update_flows'), \
                patch.object(self.tgn, 'start_traffic') as start:
            self.tgn.set_line_rate(self.name, .01, start_traffic_time=0)
        start.assert_not_called()

    def test_setter_starts_a_stopped_flow(self):
        with patch.object(self.tgn, 'start_traffic',
                          wraps=self.tgn.start_traffic) as start:
            self.tgn.set_packet_rate(self.name, 2500, start_traffic_time=0)
        start.assert_called_once_with(wait_time=0, traffic_streams=[self.name])

    def test_missing_state_cannot_establish_success(self):
        with patch.object(self.tgn, '_flow_transmit_states', return_value={}):
            with self.assertRaisesRegex(GenieTgnError, 'missing metrics'):
                self.tgn.set_packet_rate(self.name, 2500, start_traffic_time=0)

    def test_disabled_start_never_queries_or_changes_transmit_state(self):
        with patch.object(self.tgn, '_flow_transmit_states') as states, \
                patch.object(self.tgn, 'start_traffic') as start:
            self.tgn.set_packet_rate(self.name, 2500, start_traffic=False)
            self.tgn.set_packet_size_fixed(self.name, 256, start_traffic=False)
        states.assert_not_called()
        start.assert_not_called()

    def test_flow_group_names_the_flow(self):
        '''A flow group is the flow, so naming one addresses that flow.'''
        other = self.second_flow()
        self.tgn.apply_traffic(wait_time=0)
        self.tgn.set_packet_rate(self.name, 700, flow_group=other,
                                 start_traffic=False)
        self.assertEqual(self.tgn.get_packet_rate(self.name,
                                                  flow_group=other), 700)
        self.assertEqual(self.tgn.get_packet_rate(self.name), 1000)

    def test_unknown_stream_is_reported(self):
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.get_packet_size('nosuchflow')
        self.assertIn('nosuchflow', str(caught.exception))


class TestStreamControlCompatibility(IxiaOtgTestCase):
    '''Per-stream start and stop, and the flow group that is a flow.'''

    def setUp(self):
        super().setUp()
        self.name = self.add_flow()
        self.tgn.apply_traffic(wait_time=0)

    def test_start_and_stop_one_stream(self):
        self.assertTrue(self.tgn.start_traffic_stream(self.name,
                                                      check_stream=False,
                                                      wait_time=0))
        self.assertTrue(self.tgn.stop_traffic_stream(self.name, wait_time=0))

    def test_start_checks_the_stream_is_transmitting(self):
        self.assertTrue(self.tgn.start_traffic_stream(self.name,
                                                      check_stream=True,
                                                      wait_time=0,
                                                      max_time=30))

    def test_stale_nonzero_frames_do_not_prove_transmission(self):
        with patch.object(self.tgn, 'get_stats', return_value={
                self.name: {'Tx Frames': 100}}), \
                patch.object(self.tgn, '_flow_transmit_states',
                             return_value={self.name: 'started'}):
            with self.assertRaisesRegex(GenieTgnError, 'no new frames'):
                self.tgn._check_stream_transmitting(self.name, max_time=0)

    def test_increasing_counters_with_stopped_state_are_rejected(self):
        counts = iter([100, 101, 102])
        with patch.object(self.tgn, 'get_stats', side_effect=lambda **kw: {
                self.name: {'Tx Frames': next(counts)}}), \
                patch.object(self.tgn, '_flow_transmit_states',
                             return_value={self.name: 'stopped'}), \
                patch('genie.trafficgen.otg.implementation.time.time',
                      side_effect=[0, 0, 0, 2]), \
                patch('genie.trafficgen.otg.implementation.time.sleep'):
            with self.assertRaisesRegex(GenieTgnError, 'no new frames'):
                self.tgn._check_stream_transmitting(self.name, max_time=1)

    def test_missing_or_invalid_sample_does_not_make_stale_frames_fresh(self):
        for invalid in ({}, {self.name: {}},
                        {self.name: {'Tx Frames': None}},
                        {self.name: {'Tx Frames': '*'}},
                        {self.name: {'Tx Frames': -1}},
                        {self.name: {'Tx Frames': float('nan')}},
                        {self.name: {'Tx Frames': float('inf')}}):
            with self.subTest(sample=invalid):
                samples = iter([invalid, {self.name: {'Tx Frames': 100}},
                                {self.name: {'Tx Frames': 100}}])
                clock = [0]
                with patch.object(self.tgn, 'get_stats',
                                  side_effect=samples), \
                        patch.object(self.tgn, '_flow_transmit_states',
                                     return_value={self.name: 'started'}), \
                        patch('genie.trafficgen.otg.implementation.time.time',
                              side_effect=lambda clock=clock: clock[0]), \
                        patch('genie.trafficgen.otg.implementation.time.sleep',
                              side_effect=lambda _, clock=clock: (
                                  clock.__setitem__(0, clock[0] + 1))):
                    with self.assertRaisesRegex(GenieTgnError, 'no new frames'):
                        self.tgn._check_stream_transmitting(self.name,
                                                           max_time=1)

    def test_counter_baseline_is_reestablished_after_missing_sample(self):
        samples = iter([{self.name: {'Tx Frames': 100}}, {},
                        {self.name: {'Tx Frames': 200}},
                        {self.name: {'Tx Frames': 201}}])
        clock = [0]
        with patch.object(self.tgn, 'get_stats',
                          side_effect=lambda **kw: next(samples)), \
                patch.object(self.tgn, '_flow_transmit_states',
                             return_value={self.name: 'started'}), \
                patch('genie.trafficgen.otg.implementation.time.time',
                      side_effect=lambda: clock[0]), \
                patch('genie.trafficgen.otg.implementation.time.sleep',
                      side_effect=lambda _: clock.__setitem__(0, clock[0] + 1)):
            self.assertTrue(self.tgn._check_stream_transmitting(self.name,
                                                              max_time=4))
        self.assertEqual(clock[0], 3)

    def test_starting_one_stream_leaves_the_others_alone(self):
        other = self.second_flow()
        self.tgn.apply_traffic(wait_time=0)
        self.tgn.start_traffic_stream(self.name, check_stream=True,
                                      wait_time=0, max_time=30)
        stats = self.tgn.get_stats(view='Flow Statistics')
        self.assertGreater(stats[self.name]['Tx Frames'], 0)
        self.assertEqual(stats[other]['Tx Frames'], 0)

    def test_starting_an_unknown_stream_is_refused(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.start_traffic_stream('nosuchflow', check_stream=False,
                                          wait_time=0)

    def test_a_stream_is_its_own_flow_group(self):
        self.assertEqual(self.tgn.get_flow_group_names(self.name),
                         [self.name])

    def test_flow_group_start_and_stop(self):
        self.assertTrue(self.tgn.start_flow_group(self.name, self.name,
                                                  wait_time=0))
        self.assertTrue(self.tgn.stop_flow_group(self.name, self.name,
                                                 wait_time=0))


class TestStatisticsCompatibility(IxiaOtgTestCase):
    '''The IxiaNative statistics calls, over the OTG metrics.'''

    def setUp(self):
        super().setUp()
        self.name = self.add_flow()
        self.tgn.start_traffic(wait_time=0)

    def test_views_are_named(self):
        self.assertIn('Flow Statistics', self.tgn.get_all_statistics_views())

    def test_flow_statistics_field(self):
        self.assertIsNotNone(
            self.tgn.get_flow_statistics_data(self.name, 'Tx Frames'))

    def test_traffic_item_statistics_field(self):
        self.assertIsNotNone(
            self.tgn.get_traffic_items_statistics_data(self.name,
                                                       'Rx Frames'))

    def test_unknown_column_lists_the_columns(self):
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.get_flow_statistics_data(self.name, 'No Such Column')
        self.assertIn('Tx Frames', str(caught.exception))

    def test_unknown_stream_lists_the_streams(self):
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.get_flow_statistics_data('nosuchflow', 'Tx Frames')
        self.assertIn(self.name, str(caught.exception))

    def test_flow_statistics_table_is_remembered(self):
        created = self.tgn.create_flow_statistics_table(display=False)
        self.assertIs(self.tgn.get_flow_statistics_table(), created)
        self.assertIn(self.name, created.get_string())

    def test_table_before_creation_is_refused(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.get_flow_statistics_table()

    def test_table_columns_can_be_chosen(self):
        table = self.tgn.create_flow_statistics_table(
            flow_stats_columns=['Tx Frames'], display=False)
        self.assertIn('Tx Frames', table.field_names)

    def test_unknown_table_column_is_refused(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.create_flow_statistics_table(
                flow_stats_columns=['No Such Column'], display=False)

    def test_table_exports_to_csv(self):
        path = os.path.join(tempfile.mkdtemp(), 'flows.csv')
        self.tgn.create_flow_statistics_table(display=False,
                                              export_to_filename=path)
        self.assertIn(self.name, open(path).read())

    def test_traffic_item_statistics_table(self):
        table = self.tgn.get_traffic_item_statistics_table()
        self.assertIn(self.name, table.get_string())

    def test_snapshot_writes_a_csv(self):
        directory = tempfile.mkdtemp()
        path = self.tgn.save_statistics_snapshot_csv(
            'Flow Statistics', csv_windows_path=directory,
            csv_file_name='snapshot')
        self.assertTrue(path.endswith('snapshot.csv'))
        self.assertIn(self.name, open(path).read())

    def test_snapshot_ignores_an_ixnetwork_windows_path(self):
        '''IxiaNative defaults this to a path on the IxNetwork host.

        The snapshot then lands next to the run artifacts, which outside
        easypy is the working directory.
        '''
        directory = tempfile.mkdtemp()
        previous = os.getcwd()
        os.chdir(directory)
        try:
            path = self.tgn.save_statistics_snapshot_csv(
                'Flow Statistics', csv_windows_path='C:\\Users\\',
                csv_file_name='snapshot')
            self.assertNotIn('\\', path)
            self.assertIn(self.name, open(path).read())
        finally:
            os.chdir(previous)

    def test_snapshot_of_an_unknown_view_is_refused(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.save_statistics_snapshot_csv('No Such View')

    def test_traffic_items_from_a_profile_table(self):
        profile = self.tgn.create_traffic_streams_table()
        self.assertIn(self.name,
                      self.tgn.get_traffic_items_from_genie_view(profile))

    def test_flow_groups_loss_check(self):
        '''The CSV arguments IxNetwork needs are accepted and ignored.'''
        results = self.tgn.check_flow_groups_loss(
            traffic_streams=[self.name], csv_windows_path='C:\\Users\\',
            csv_file_name='Flow_Statistics', display=False)
        measured = results[0]['stream'][self.name]
        self.assertEqual(measured['Loss %'], 0.0)
        self.assertEqual(measured['State'], 'started')


class TestEcmpTrafficLoss(IxiaOtgTestCase):
    '''Transmitted against received, summed over the ECMP paths.'''

    def setUp(self):
        super().setUp()
        self.name = self.add_flow()
        self.tgn.start_traffic(wait_time=0)

    def test_matching_counters_pass(self):
        results = self.tgn.check_ecmp_traffic_loss([self.name],
                                                   check_iteration=1,
                                                   check_interval=0)
        tx, rx, within = results[self.name]
        self.assertTrue(within, 'mock traffic is lossless, so this passes')
        self.assertEqual(tx, rx)

    def test_a_single_name_is_accepted(self):
        self.assertIn(self.name, self.tgn.check_ecmp_traffic_loss(
            self.name, check_iteration=1, check_interval=0))

    def test_loss_beyond_the_tolerance_fails_the_check(self):
        '''IxiaNative raises on ECMP loss, so this one has to as well.'''
        self.tgn.engine.set_flow_loss(self.name, loss_pct=20)
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.check_ecmp_traffic_loss([self.name], tolerance=0.05,
                                             check_iteration=1,
                                             check_interval=0)
        self.assertIn(self.name, str(caught.exception))

    def test_the_check_runs_at_least_once(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.check_ecmp_traffic_loss([self.name], check_iteration=0)

    def test_unknown_item_is_reported(self):
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.check_ecmp_traffic_loss(['nosuchflow'],
                                             check_iteration=1,
                                             check_interval=0)
        self.assertIn('nosuchflow', str(caught.exception))


class TestConfigurationCompatibility(IxiaOtgTestCase):
    '''Saving the configuration and reading the traffic state.'''

    def setUp(self):
        super().setUp()
        self.name = self.add_flow()
        self.tgn.apply_traffic(wait_time=0)

    def test_save_configuration_writes_the_otg_model(self):
        path = os.path.join(tempfile.mkdtemp(), 'config.json')
        self.assertEqual(self.tgn.save_configuration(path), path)
        self.assertIn(self.name, open(path).read())

    def test_save_configuration_reports_a_bad_path(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.save_configuration('/nonexistent-directory/config.json')

    def test_regenerate_commits_the_streams(self):
        self.assertTrue(self.tgn.regenerate_all_traffic_items())

    def test_traffic_state_follows_the_flows(self):
        self.assertEqual(self.tgn.get_traffic_attribute('state'), 'stopped')
        self.tgn.start_traffic(wait_time=0)
        self.assertEqual(self.tgn.get_traffic_attribute('state'), 'started')
        self.assertTrue(self.tgn.get_traffic_attribute('isTrafficRunning'))

    def test_unknown_attribute_names_what_is_served(self):
        with self.assertRaises(GenieTgnError) as caught:
            self.tgn.get_traffic_attribute('refreshLearnedInfoBeforeApply')
        self.assertIn('get_config()', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
