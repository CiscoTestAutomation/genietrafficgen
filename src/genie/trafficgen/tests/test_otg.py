import os
import json
import logging
import secrets
import shutil
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import yaml

from pyats.topology import loader

from genie.harness.exceptions import GenieTgnError
from genie.trafficgen.otg import implementation, mock
from genie.trafficgen import ixnetwork

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


class TestPlatformSelection(unittest.TestCase):
    '''This plugin serves the OTG controllers, and says so when it does not.'''

    def _instantiate(self, platform=None):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg1
        if platform is not None:
            dev.platform = platform
        return dev.instantiate(via='tgn', alias='tgn')

    def test_device_without_a_platform_is_served(self):
        self.assertEqual(self._instantiate().platform, 'ixia')

    def test_ixia_platform_is_served(self):
        self.assertEqual(self._instantiate('ixia').platform, 'ixia')

    def test_platform_is_matched_case_insensitively(self):
        self.assertEqual(self._instantiate('IXIA').platform, 'ixia')

    def test_device_type_is_not_read_as_a_platform(self):
        testbed = loader.load(TESTBED)
        self.assertEqual(testbed.devices.otg1.type, 'tgn')
        self.assertEqual(self._instantiate().platform, 'ixia')

    def test_unserved_platform_names_the_entry_point(self):
        with self.assertRaises(GenieTgnError) as ctx:
            self._instantiate('a-generator-of-our-own')
        message = str(ctx.exception)
        self.assertIn('a-generator-of-our-own', message)
        self.assertIn(implementation.TRAFFICGEN_ENTRYPOINT, message)


class TestSnappiLazyImport(unittest.TestCase):
    '''The default dependency remains lazily imported by the OTG plugin.'''

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
        self.assertIn('pip install genie.trafficgen', str(ctx.exception))

    def test_mock_transport_does_not_require_importable_snappi(self):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg1
        tgn = dev.instantiate(via='tgn', alias='tgn')
        with patch.dict('sys.modules', {'snappi': None}):
            self.assertTrue(tgn.connect())
            self.assertTrue(tgn.connected)
            self.assertTrue(tgn.disconnect())

    def test_non_mock_transport_requires_snappi(self):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg3
        tgn = dev.instantiate(via='tgn', alias='tgn')
        with patch.dict('sys.modules', {'snappi': None}):
            with self.assertRaises(GenieTgnError):
                tgn.connect()
        self.assertFalse(tgn.connected)


class TestSnappiExtension(unittest.TestCase):
    '''Extensions named by 'ext' are installed on request, not by default.'''

    def test_missing_extension_names_the_install_extra(self):
        with patch.dict('sys.modules', {'snappi_ixnetwork': None}):
            with self.assertRaises(GenieTgnError) as ctx:
                implementation.import_snappi_extension('ixnetwork')
        self.assertIn('pip install genie.trafficgen[ixnetwork]',
                      str(ctx.exception))

    def test_missing_third_party_extension_names_the_snappi_extra(self):
        with patch.dict('sys.modules', {'snappi_trex': None}):
            with self.assertRaises(GenieTgnError) as ctx:
                implementation.import_snappi_extension('trex')
        self.assertIn('pip install snappi[trex]', str(ctx.exception))

    def test_connect_requires_the_extension_before_calling_snappi(self):
        testbed = loader.load(TESTBED)
        dev = testbed.devices.otg3
        dev.connections.tgn['ext'] = 'ixnetwork'
        tgn = dev.instantiate(via='tgn', alias='tgn')
        snappi = Mock()
        with patch.object(implementation, 'import_snappi',
                          return_value=snappi), \
                patch.dict('sys.modules', {'snappi_ixnetwork': None}):
            with self.assertRaises(GenieTgnError) as ctx:
                tgn.connect()
        self.assertIn('snappi_ixnetwork', str(ctx.exception))
        snappi.api.assert_not_called()
        self.assertFalse(tgn.connected)


class TestIxNetworkLicensingBridge(unittest.TestCase):
    '''Native OTG configures controller licensing before creating Snappi.'''

    @staticmethod
    def _ixnet(initial=None):
        state = dict(initial or {
            '-licensingServers': [],
            '-mode': 'perpetual',
            '-tier': 'tier1',
        })
        ixnet = Mock()
        ixnet.OK = 'ok'
        ixnet.connect.return_value = ixnet.OK
        ixnet.disconnect.return_value = ixnet.OK
        ixnet.getRoot.return_value = 'root'
        ixnet.getList.side_effect = (
            lambda obj, name: ['globals'] if name == 'globals'
            else ['licensing'])
        ixnet.getAttribute.side_effect = lambda obj, attr: state[attr]

        def set_attribute(obj, attr, value):
            state[attr] = value

        ixnet.setAttribute.side_effect = set_attribute
        return ixnet, state

    def _configure(self, ixnet, **kwargs):
        with patch('genie.trafficgen.ixnetwork._import_ixnet',
                   return_value=lambda: ixnet):
            return implementation.configure_ixnetwork_licensing(**kwargs)

    def test_configures_all_licensing_keys_before_disconnect(self):
        ixnet, state = self._ixnet()
        self.assertTrue(self._configure(
            ixnet, controller_host='192.0.2.10', tcl_port=8020,
            version='9.30',
            license_servers='198.51.100.10; 198.51.100.11; 198.51.100.10',
            license_mode='subscription', license_tier='tier2'))

        ixnet.connect.assert_called_once_with(
            '192.0.2.10', '-port', 8020, '-version', '9.30',
            '-setAttribute', 'strict', '-licenseMode', 'subscription',
            '-licenseTier', 'tier2')
        ixnet.setAttribute.assert_any_call(
            'licensing', '-licensingServers',
            ['198.51.100.10', '198.51.100.11'])
        ixnet.setAttribute.assert_any_call(
            'licensing', '-mode', 'subscription')
        ixnet.setAttribute.assert_any_call('licensing', '-tier', 'tier2')
        self.assertEqual(state['-mode'], 'subscription')
        self.assertEqual(state['-tier'], 'tier2')
        self.assertEqual(state['-licensingServers'],
                         ['198.51.100.10', '198.51.100.11'])
        ixnet.disconnect.assert_called_once_with()

    def test_licensing_lifecycle_logs_are_redacted_and_precede_snappi(self):
        ixnet, _ = self._ixnet()
        events = []
        ixnet.connect.side_effect = (
            lambda *args: events.append('tcl_connect') or ixnet.OK)
        ixnet.disconnect.side_effect = (
            lambda: events.append('tcl_disconnect') or ixnet.OK)
        device, tgn = self._real_otg(
            ixia_license_server_ip='198.51.100.10;198.51.100.11',
            ixnetwork_license_mode='subscription',
            ixnetwork_license_tier='tier2')
        snappi = Mock()
        snappi.api.side_effect = lambda **kwargs: (
            events.append('snappi') or Mock(config=Mock(return_value=Mock())))

        class RecordingHandler(logging.Handler):
            def emit(self, record):
                events.append(record.getMessage())

        handler = RecordingHandler()
        old_level = ixnetwork.log.level
        ixnetwork.log.addHandler(handler)
        ixnetwork.log.setLevel(logging.INFO)
        try:
            with patch.object(ixnetwork, '_import_ixnet',
                              return_value=lambda: ixnet), \
                    patch.object(implementation, 'import_snappi',
                                 return_value=snappi), \
                    patch.object(implementation, 'import_snappi_extension'), \
                    patch.object(tgn, '_populate_ports_from_testbed'):
                self.assertTrue(tgn.connect())

            lifecycle_logs = [event for event in events if isinstance(event, str)
                              and 'IxNetwork' in event]
            self.assertEqual(len(lifecycle_logs), 3)
            self.assertIn('Starting temporary IxNetwork Tcl licensing session',
                          lifecycle_logs[0])
            self.assertIn('license_server_count=2', lifecycle_logs[0])
            self.assertIn('license_mode=subscription', lifecycle_logs[0])
            self.assertIn('license_tier=tier2', lifecycle_logs[0])
            self.assertIn('strict read-back verified', lifecycle_logs[1])
            self.assertIn('disconnected before native OTG/Snappi',
                          lifecycle_logs[2])
            self.assertLess(events.index(lifecycle_logs[2]),
                            events.index('snappi'))
            for sensitive_value in ('192.0.2.10', '8020', '198.51.100.10',
                                    '198.51.100.11', 'api-key'):
                self.assertNotIn(sensitive_value, '\n'.join(lifecycle_logs))
        finally:
            ixnetwork.log.removeHandler(handler)
            ixnetwork.log.setLevel(old_level)
            tgn.disconnect()
            device.destroy()

    def test_individual_license_server_setting_is_supported(self):
        ixnet, state = self._ixnet()
        self._configure(
            ixnet, controller_host='192.0.2.10', tcl_port=8020,
            version='9.30', license_servers=['198.51.100.10'])
        self.assertEqual(state['-licensingServers'], ['198.51.100.10'])
        self.assertNotIn('-licenseMode', ixnet.connect.call_args[0])
        self.assertNotIn('-licenseTier', ixnet.connect.call_args[0])

    def test_individual_license_mode_setting_is_supported(self):
        ixnet, state = self._ixnet()
        self._configure(
            ixnet, controller_host='192.0.2.10', tcl_port=8020,
            version='9.30', license_mode='subscription')
        self.assertEqual(state['-mode'], 'subscription')
        self.assertNotIn('-licenseTier', ixnet.connect.call_args[0])
        ixnet.setAttribute.assert_any_call(
            'licensing', '-mode', 'subscription')

    def test_individual_license_tier_setting_is_supported(self):
        ixnet, state = self._ixnet()
        self._configure(
            ixnet, controller_host='192.0.2.10', tcl_port=8020,
            version='9.30', license_tier='tier2')
        self.assertEqual(state['-tier'], 'tier2')
        self.assertNotIn('-licenseMode', ixnet.connect.call_args[0])
        ixnet.setAttribute.assert_any_call('licensing', '-tier', 'tier2')

    def test_credentials_supply_an_api_key_without_closing_the_controller(self):
        ixnet, _ = self._ixnet()
        ixnet.getApiKey.return_value = 'api-key'
        self._configure(
            ixnet, controller_host='192.0.2.10', tcl_port=8020,
            version='9.30', license_mode='subscription',
            credentials={'default': {'username': 'user', 'password': 'pass'}})
        ixnet.getApiKey.assert_called_once_with(
            '192.0.2.10', '-username', 'user', '-password', 'pass')
        connect_args = ixnet.connect.call_args[0]
        self.assertIn('-apiKey', connect_args)
        self.assertNotIn('-closeServerOnDisconnect', connect_args)

    def test_anonymous_connection_does_not_request_an_api_key(self):
        ixnet, _ = self._ixnet()
        self._configure(
            ixnet, controller_host='192.0.2.10', tcl_port=8020,
            version='9.30', license_mode='subscription')
        ixnet.getApiKey.assert_not_called()

    def test_readback_mismatch_fails_and_disconnects(self):
        ixnet, _ = self._ixnet()
        readback = {'-licensingServers': [], '-mode': 'perpetual',
                    '-tier': 'tier1'}
        ixnet.getAttribute.side_effect = lambda obj, attr: readback[attr]
        with self.assertRaisesRegex(GenieTgnError, 'did not retain'):
            self._configure(
                ixnet, controller_host='192.0.2.10', tcl_port=8020,
                version='9.30', license_servers=['198.51.100.10'])
        ixnet.disconnect.assert_called_once_with()

    def test_unchanged_license_attributes_are_only_read_back(self):
        ixnet, _ = self._ixnet()
        self.assertTrue(ixnetwork.apply_ixnetwork_license_settings(
            ixnet, license_mode='perpetual', license_tier='tier1', strict=True))
        ixnet.setAttribute.assert_not_called()
        ixnet.commit.assert_not_called()
        self.assertEqual(ixnet.getAttribute.call_args_list, [
            call('licensing', '-mode'),
            call('licensing', '-tier'),
            call('licensing', '-mode'),
            call('licensing', '-tier'),
        ])

    def test_mode_and_tier_readback_mismatches_fail_and_disconnect(self):
        for key, value in (('license_mode', 'subscription'),
                           ('license_tier', 'tier2')):
            with self.subTest(key=key):
                ixnet, _ = self._ixnet()
                ixnet.setAttribute.side_effect = None
                with self.assertRaisesRegex(GenieTgnError, 'did not retain'):
                    self._configure(
                        ixnet, controller_host='192.0.2.10', tcl_port=8020,
                        version='9.30', **{key: value})
                ixnet.disconnect.assert_called_once_with()

    def test_legacy_license_errors_remain_warning_only(self):
        ixnet, _ = self._ixnet()
        ixnet.commit.side_effect = RuntimeError('commit rejected')
        with self.assertLogs(ixnetwork.log, level='WARNING') as logs:
            self.assertFalse(ixnetwork.apply_ixnetwork_license_settings(
                ixnet, license_mode='subscription', strict=False))
        self.assertIn('commit rejected', logs.output[0])

    def test_rejected_connect_does_not_disconnect_or_apply_settings(self):
        ixnet, _ = self._ixnet()
        ixnet.connect.return_value = 'rejected'
        with self.assertRaisesRegex(GenieTgnError, 'licensing connection'):
            self._configure(
                ixnet, controller_host='192.0.2.10', tcl_port=8020,
                version='9.30', license_mode='subscription')
        ixnet.setAttribute.assert_not_called()
        ixnet.disconnect.assert_not_called()

    def test_api_key_failure_prevents_connect(self):
        ixnet, _ = self._ixnet()
        password = secrets.token_hex(16)
        error = RuntimeError('authentication rejected')
        ixnet.getApiKey.side_effect = error
        with self.assertRaisesRegex(GenieTgnError, 'API key') as raised:
            self._configure(
                ixnet, controller_host='192.0.2.10', tcl_port=8020,
                version='9.30', license_mode='subscription',
                credentials={'default': {'username': 'user', 'password': password}})
        self.assertIs(raised.exception.__cause__, error)
        ixnet.connect.assert_not_called()
        ixnet.disconnect.assert_not_called()

    def test_disconnect_rejection_fails_an_otherwise_successful_session(self):
        ixnet, _ = self._ixnet()
        ixnet.disconnect.return_value = 'rejected'
        with self.assertRaisesRegex(GenieTgnError, 'licensing disconnect'):
            self._configure(
                ixnet, controller_host='192.0.2.10', tcl_port=8020,
                version='9.30', license_mode='subscription')
        ixnet.disconnect.assert_called_once_with()

    def test_disconnect_exception_keeps_its_cause(self):
        ixnet, _ = self._ixnet()
        error = RuntimeError('disconnect failed')
        ixnet.disconnect.side_effect = error
        with self.assertRaisesRegex(GenieTgnError, 'disconnect failed') as raised:
            self._configure(
                ixnet, controller_host='192.0.2.10', tcl_port=8020,
                version='9.30', license_mode='subscription')
        self.assertIs(raised.exception.__cause__, error)

    def test_cleanup_failure_preserves_the_primary_licensing_error(self):
        ixnet, _ = self._ixnet()
        error = GenieTgnError('primary licensing failure')
        ixnet.commit.side_effect = error
        ixnet.disconnect.side_effect = RuntimeError('disconnect failed')
        with self.assertLogs(ixnetwork.log, level='WARNING') as logs:
            with self.assertRaises(GenieTgnError) as raised:
                self._configure(
                    ixnet, controller_host='192.0.2.10', tcl_port=8020,
                    version='9.30', license_mode='subscription')
        self.assertIs(raised.exception, error)
        self.assertIn('after an earlier error', logs.output[0])
        ixnet.disconnect.assert_called_once_with()

    def test_invalid_license_scalars_prevent_controller_operations(self):
        for key in ('ixnetwork_license_mode', 'ixnetwork_license_tier'):
            for value in (None, '', '  ', 1):
                with self.subTest(key=key, value=value):
                    device, tgn = self._real_otg(**{key: value})
                    try:
                        with patch.object(implementation,
                                          'configure_ixnetwork_licensing') as bridge:
                            with self.assertRaisesRegex(GenieTgnError, key):
                                tgn.connect()
                        bridge.assert_not_called()
                        self.assertFalse(tgn.connected)
                    finally:
                        device.destroy()

    def test_license_scalar_trimming_and_url_host_fallback(self):
        device, tgn = self._real_otg(
            ip=None, ixnetwork_license_mode=' subscription ',
            ixnetwork_license_tier=' tier2 ')
        try:
            with patch.object(implementation,
                              'configure_ixnetwork_licensing') as bridge:
                tgn._configure_ixnetwork_licensing()
            self.assertEqual(bridge.call_args.kwargs['controller_host'],
                             '192.0.2.10')
            self.assertEqual(bridge.call_args.kwargs['license_mode'],
                             'subscription')
            self.assertEqual(bridge.call_args.kwargs['license_tier'], 'tier2')
        finally:
            device.destroy()

    def _real_otg(self, **connection_values):
        testbed = loader.load(TESTBED)
        # otg1 names Otg directly, keeping this isolated from abstraction
        # discovery of unrelated optional traffic-generator packages.
        device = testbed.devices.otg1
        device.connections.tgn.update({
            'transport': 'https',
            'location': 'https://192.0.2.10:8443',
            'ext': 'ixnetwork',
            'ixnetwork_tcl_port': 8020,
            'ixnetwork_version': '9.30',
            **connection_values,
        })
        return device, device.instantiate(via='tgn', alias='tgn')

    def test_connect_orders_license_bridge_before_snappi_and_ports(self):
        device, tgn = self._real_otg(ixnetwork_license_mode='subscription')
        events = []
        snappi = Mock()
        snappi.api.side_effect = lambda **kwargs: (
            events.append('snappi') or Mock(config=Mock(return_value=Mock())))
        try:
            with patch.object(implementation, 'configure_ixnetwork_licensing',
                              side_effect=lambda **kwargs: events.append('license')), \
                    patch.object(implementation, 'import_snappi',
                                 return_value=snappi), \
                    patch.object(implementation, 'import_snappi_extension'), \
                    patch.object(tgn, '_populate_ports_from_testbed',
                                 side_effect=lambda: events.append('ports')):
                self.assertTrue(tgn.connect())
            self.assertEqual(events, ['license', 'snappi', 'ports'])
        finally:
            tgn.disconnect()
            device.destroy()

    def test_license_failure_prevents_snappi_creation(self):
        device, tgn = self._real_otg(ixnetwork_license_mode='subscription')
        try:
            with patch.object(implementation, 'configure_ixnetwork_licensing',
                              side_effect=GenieTgnError('licensing failed')), \
                    patch.object(implementation, 'import_snappi') as snappi:
                with self.assertRaisesRegex(GenieTgnError, 'licensing failed'):
                    tgn.connect()
            snappi.assert_not_called()
            self.assertFalse(tgn.connected)
        finally:
            device.destroy()

    def test_missing_tcl_parameters_prevent_snappi_creation(self):
        testbed = loader.load(TESTBED)
        device = testbed.devices.otg1
        device.connections.tgn.update({
            'transport': 'https',
            'location': 'https://192.0.2.10:8443',
            'ext': 'ixnetwork',
            'ixnetwork_license_mode': 'subscription',
        })
        tgn = device.instantiate(via='tgn', alias='tgn')
        try:
            with patch.object(implementation, 'import_snappi') as snappi:
                with self.assertRaisesRegex(GenieTgnError,
                                             'ixnetwork_tcl_port'):
                    tgn.connect()
            snappi.assert_not_called()
        finally:
            device.destroy()

    def test_license_keys_are_rejected_for_mock_and_other_backends(self):
        testbed = loader.load(TESTBED)
        mock_device = testbed.devices.otg1
        mock_device.connections.tgn.update({
            'ext': 'ixnetwork',
            'ixia_license_server_ip': '198.51.100.10',
            'ixnetwork_tcl_port': 8020,
            'ixnetwork_version': '9.30',
        })
        mock_tgn = mock_device.instantiate(via='tgn', alias='tgn')
        try:
            with self.assertRaisesRegex(GenieTgnError, 'transport: mock'):
                mock_tgn.connect()
        finally:
            mock_device.destroy()

        device, tgn = self._real_otg(
            ext='trex', ixnetwork_license_mode='subscription')
        try:
            with self.assertRaisesRegex(GenieTgnError, 'ext: ixnetwork'):
                tgn.connect()
        finally:
            device.destroy()


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
        self.assertEqual(flow.packet[1].target_protocol_addr.value, '10.1.1.1')
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
        config = self.tgn.api.config()
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

    def test_round_trip_preserves_devices_and_captures(self):
        config = self.build_config()
        device = config.devices.add(name='host')
        ethernet = device.ethernets.add(name='eth1', mac='00:00:01:00:00:01')
        ethernet.connection.port_name = 'p1'
        ethernet.ipv4_addresses.add(name='v4', address='192.0.2.2',
                                    gateway='192.0.2.1', prefix=24)
        ethernet.ipv6_addresses.add(name='v6', address='2001:db8::2',
                                    gateway='2001:db8::1', prefix=64)
        capture = config.captures.add(name='c1')
        capture.port_names = ['p2']
        capture.format = 'pcapng'
        capture.packet_size = 128
        self.tgn.set_config(config.serialize())
        restored = self.tgn.config.to_dict()
        self.assertEqual(restored['devices'], config.to_dict()['devices'])
        self.assertEqual(restored['captures'], config.to_dict()['captures'])

    def test_set_config_rejects_a_file_path(self):
        # snappi accepts any text, and a path would push an empty
        # configuration
        lenient = Mock()
        with patch.object(self.tgn.api, 'config', return_value=lenient):
            with self.assertRaises(GenieTgnError):
                self.tgn.set_config('/tmp/otg_config.json')
        lenient.deserialize.assert_not_called()

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

    def test_control_state_and_metrics_requests_as_data(self):
        # what a trigger datafile can hold: a mapping or YAML text
        self.tgn.set_config(self.build_config())

        self.tgn.set_state({'choice': 'traffic', 'traffic': {
            'choice': 'flow_transmit',
            'flow_transmit': {'state': 'start', 'flow_names': ['f1']}}})
        metrics = self.tgn.get_metrics('choice: flow\nflow:\n'
                                       '  flow_names: [f1]\n')
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

    def test_start_all_protocols_retries_a_busy_controller(self):
        attempts = []
        engine = self.tgn.translation_engine

        def send_arp(wait_time=0):
            attempts.append(wait_time)
            if len(attempts) < 3:
                raise RuntimeError(
                    'getTopologyStatus exec not allowed currently since an '
                    '(Clearing Statistics...) operation is in progress.')
            return True

        with patch.object(engine, 'send_arp', side_effect=send_arp), \
                patch('genie.trafficgen.otg.implementation.time.sleep') as wait:
            self.assertTrue(self.tgn.start_all_protocols(wait_time=0))

        self.assertEqual(len(attempts), 3)
        self.assertEqual(wait.call_count, 2)

    def test_start_all_protocols_does_not_retry_real_errors(self):
        engine = self.tgn.translation_engine

        with patch.object(engine, 'send_arp',
                          side_effect=RuntimeError('invalid endpoint')) as send:
            with self.assertRaisesRegex(RuntimeError, 'invalid endpoint'):
                self.tgn.start_all_protocols(wait_time=0)

        send.assert_called_once_with(wait_time=0)

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
        # Keep the connection's active in-memory configuration untouched;
        # this fixture is only the file/payload supplied to the API under test.
        config = self.tgn.api.config()
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


class TestTrafficProfileUpdate(OtgTestCase):
    '''Rate and frame size can be changed without reloading the configuration.'''

    def test_rate_is_updated(self):
        name = self.add_flow()
        self.assertTrue(self.tgn.update_traffic_profile(rate=2000,
                                                        wait_time=0))
        self.assertEqual(float(self.flow(name).rate.pps), 2000)

    def test_frame_size_is_updated(self):
        name = self.add_flow()
        self.assertTrue(self.tgn.update_traffic_profile(size=512,
                                                        wait_time=0))
        self.assertEqual(int(self.flow(name).size.fixed), 512)

    def test_only_the_named_streams_are_updated(self):
        first = self.add_flow()
        second = self.add_flow()
        before = float(self.flow(second).rate.pps)

        self.tgn.update_traffic_profile(traffic_streams=[first], rate=750,
                                        wait_time=0)

        self.assertEqual(float(self.flow(first).rate.pps), 750)
        self.assertEqual(float(self.flow(second).rate.pps), before)

    def test_a_single_stream_name_is_accepted(self):
        name = self.add_flow()
        self.tgn.update_traffic_profile(traffic_streams=name, rate=300,
                                        wait_time=0)
        self.assertEqual(float(self.flow(name).rate.pps), 300)

    def test_an_unknown_stream_raises(self):
        self.add_flow()
        with self.assertRaises(GenieTgnError):
            self.tgn.update_traffic_profile(traffic_streams=['nope'], rate=10,
                                            wait_time=0)

    def test_invalid_rate_attribute_has_no_side_effects(self):
        name = self.add_flow()
        before = self.tgn.config.serialize()
        with patch.object(self.tgn.translation_engine, 'commit') as commit, \
                patch.object(self.tgn.api, 'update_flows') as update:
            with self.assertRaisesRegex(GenieTgnError, 'rate_attribute'):
                self.tgn.update_traffic_profile(
                    [name], rate=777, rate_attribute='ppss')
        commit.assert_not_called()
        update.assert_not_called()
        self.assertEqual(self.tgn.config.serialize(), before)
        self.assertFalse(hasattr(self.flow(name).rate, 'ppss'))

    def test_bit_rate_has_no_stale_pps_reference(self):
        name = self.add_flow()
        self.tgn.update_traffic_profile(
            [name], rate=10, rate_attribute='mbps')
        before = self.flow(name).rate.serialize()
        self.assertEqual(self.tgn.translation_engine.get_flow_expected_pps(name),
                         0)
        self.assertEqual(self.flow(name).rate.serialize(), before)

    def test_reference_does_not_read_an_inactive_choice_property(self):
        name = self.add_flow()
        previous = self.flow(name).rate

        class BitRate:
            choice = 'mbps'

            @property
            def pps(self):
                raise AssertionError('inactive PPS choice was read')

        try:
            self.flow(name).rate = BitRate()
            self.assertEqual(
                self.tgn.translation_engine.get_flow_expected_pps(name), 0)
        finally:
            self.flow(name).rate = previous

    def test_an_empty_update_raises(self):
        self.add_flow()
        with self.assertRaises(GenieTgnError):
            self.tgn.update_traffic_profile(wait_time=0)

    def test_the_new_rate_drives_the_measured_rate(self):
        name = self.add_flow()
        self.tgn.start_traffic(wait_time=0)
        time.sleep(0.2)
        self.tgn.update_traffic_profile(rate=2000, wait_time=0)
        time.sleep(0.2)

        self.assertEqual(self.tgn.get_current_packet_rate()[name], 2000)

    def test_a_rejected_update_leaves_the_configuration_alone(self):
        name = self.add_flow()
        before = float(self.flow(name).rate.pps)

        def refuse(_):
            raise RuntimeError('controller says no')

        self.tgn.api.update_flows = refuse
        with self.assertRaises(GenieTgnError):
            self.tgn.update_traffic_profile(rate=9999, wait_time=0)

        # A stale in-memory rate would make check_traffic_loss() measure
        # against a rate the controller never accepted.
        self.assertEqual(float(self.flow(name).rate.pps), before)

    def test_a_rejected_update_in_another_unit_keeps_the_rate_choice(self):
        name = self.add_flow()
        before = float(self.flow(name).rate.pps)

        def refuse(_):
            raise RuntimeError('controller says no')

        self.tgn.api.update_flows = refuse
        with self.assertRaises(GenieTgnError):
            self.tgn.update_traffic_profile(rate=1, wait_time=0,
                                            rate_attribute='percentage')

        self.assertEqual(self.flow(name).rate.choice, 'pps')
        self.assertEqual(self.tgn.get_packet_rate(name), before)


class TestConfigurationUpdate(OtgTestCase):
    '''Any named object in the configuration can be changed from a testcase.'''

    def setUp(self):
        super().setUp()
        self.flow_name = self.add_flow()

    def named(self, kind):
        return [name for name, obj
                in self.tgn._walk_named_objects(self.tgn.config, set())
                if type(obj).__name__ == kind]

    def test_objects_are_addressable_by_name(self):
        for kind in ('Port', 'Device', 'Ethernet', 'Ipv4Address', 'Flow'):
            for name in self.named(kind):
                self.assertEqual(type(self.tgn.get_config_object(name)).__name__,
                                 kind)

    def test_an_unknown_name_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.get_config_object('no_such_object')

    def test_a_property_is_updated_in_memory(self):
        name = self.named('Ipv4Address')[0]
        self.tgn.update_configuration([{'name': name, 'address': '10.9.9.9'}],  # NOSONAR test address
                                      restart=False)
        self.assertEqual(self.tgn.get_config_object(name).address, '10.9.9.9')

    def test_an_update_naming_an_unknown_object_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration([{'name': 'nope', 'address': '1.1.1.1'}],  # NOSONAR test address
                                          restart=False)

    def test_an_update_of_an_unknown_property_raises(self):
        name = self.named('Ipv4Address')[0]
        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration([{'name': name, 'nonsense': 1}],
                                          restart=False)

    def test_a_nested_property_is_not_a_partial_update_target(self):
        with self.assertRaisesRegex(GenieTgnError, 'not a scalar'):
            self.tgn.update_configuration(
                [{'name': self.flow_name, 'rate': {'pps': 2000}}],
                restart=False)

    def test_an_update_without_a_name_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration([{'address': '1.1.1.1'}],  # NOSONAR test address
                                          restart=False)

    def test_an_update_that_changes_nothing_raises(self):
        name = self.named('Ipv4Address')[0]
        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration([{'name': name}], restart=False)

    def test_nothing_is_applied_when_a_later_update_is_invalid(self):
        name = self.named('Ipv4Address')[0]
        before = self.tgn.get_config_object(name).address

        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration(
                [{'name': name, 'address': '10.9.9.9'},  # NOSONAR test address
                 {'name': 'nope', 'address': '10.9.9.10'}],  # NOSONAR test address
                restart=False)

        # Validation happens up front, so a bad second update must not leave
        # the first one half applied.
        self.assertEqual(self.tgn.get_config_object(name).address, before)

    def test_a_single_update_may_be_passed_as_a_dict(self):
        name = self.named('Ipv4Address')[0]
        self.tgn.update_configuration({'name': name, 'address': '10.8.8.8'},  # NOSONAR test address
                                      restart=False)
        self.assertEqual(self.tgn.get_config_object(name).address, '10.8.8.8')

    def test_an_empty_update_list_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration([], restart=False)

    def test_the_configuration_is_pushed_when_restarting(self):
        name = self.named('Ipv4Address')[0]
        updated = self.tgn.update_configuration(
            [{'name': name, 'address': '10.7.7.7'}],  # NOSONAR test address
            restart=True, wait_time=0)

        self.assertEqual(updated, [name])
        self.assertEqual(self.tgn.get_config_object(name).address, '10.7.7.7')

    def test_apply_configuration_uses_one_dual_stack_restart_lifecycle(self):
        self.tgn.start_traffic(wait_time=0)
        payload = json.loads(self.tgn.config.serialize())
        calls = []

        def record(name, method):
            def wrapper(*args, **kwargs):
                calls.append(name)
                return method(*args, **kwargs)
            return wrapper

        engine = self.tgn.translation_engine
        with patch.object(engine, 'stop_traffic',
                          side_effect=record('stop_traffic',
                                             engine.stop_traffic)), \
                patch.object(engine, 'stop_all_protocols',
                             side_effect=record('stop_all_protocols',
                                                engine.stop_all_protocols)), \
                patch.object(self.tgn, 'set_config',
                             side_effect=record('set_config',
                                                self.tgn.set_config)), \
                patch.object(self.tgn, 'apply_traffic',
                             side_effect=record('apply_traffic',
                                                self.tgn.apply_traffic)), \
                patch.object(self.tgn, 'start_all_protocols',
                             side_effect=record('start_all_protocols',
                                                self.tgn.start_all_protocols)), \
                patch.object(self.tgn, 'send_ns',
                             side_effect=record('send_ns', self.tgn.send_ns)), \
                patch.object(self.tgn, 'start_traffic',
                             side_effect=record('start_traffic',
                                                self.tgn.start_traffic)), \
                patch.object(self.tgn, 'clear_statistics',
                             side_effect=record('clear_statistics',
                                                self.tgn.clear_statistics)):
            self.tgn.apply_configuration(payload, wait_time=0)

        self.assertEqual(calls, [
            'stop_traffic', 'stop_all_protocols', 'set_config',
            'apply_traffic', 'start_all_protocols', 'send_ns',
            'start_traffic', 'clear_statistics',
        ])

    def test_a_failed_push_rolls_the_change_back(self):
        name = self.named('Ipv4Address')[0]
        before = self.tgn.get_config_object(name).address

        def refuse(_):
            raise RuntimeError('controller says no')

        self.tgn.api.set_config = refuse
        with self.assertRaises(GenieTgnError):
            self.tgn.update_configuration([{'name': name, 'address': '10.6.6.6'}],  # NOSONAR test address
                                          restart=True, wait_time=0)

        self.assertEqual(self.tgn.get_config_object(name).address, before)

    def test_duplicate_names_are_refused(self):
        config = self.tgn.config
        config.ports.add(name=config.ports[0].name)
        with self.assertRaises(GenieTgnError):
            self.tgn.get_config_object(self.flow_name)


class TestRouteState(OtgTestCase):
    '''Routes can be withdrawn and advertised without a configuration push.'''

    def test_routes_are_withdrawn_and_advertised(self):
        self.assertEqual(
            self.tgn.set_route_state(route_names=['r1'], state='withdraw'),
            ['r1'])
        self.assertIn('r1', self.tgn.api.engine._withdrawn)

        self.tgn.set_route_state(route_names='r1', state='advertise')
        self.assertNotIn('r1', self.tgn.api.engine._withdrawn)

    def test_an_invalid_state_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.set_route_state(route_names=['r1'], state='sideways')

    def test_no_route_ranges_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.set_route_state(state='withdraw')


class TestConfigurationArchiving(OtgTestCase):
    '''A loaded configuration is kept alongside the rest of the run artifacts.'''

    # Use the direct OTG connection class. The archive behaviour does not
    # depend on abstraction and this keeps the test independent of optional
    # third-party traffic-generator plugins discovered by the generic class.
    device_name = 'otg1'
    archived_name = 'otg1_otg_source_config.json'

    def setUp(self):
        super().setUp()
        self.workspace = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

        # The fixture must not become the active local configuration: some
        # tests prove a rejected inline replacement leaves it untouched.
        config = self.tgn.api.config()
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

    def test_apply_configuration_accepts_file_yaml_and_config_object(self):
        self.assertTrue(
            self.tgn.apply_configuration(self.source, restart=False))
        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])

        candidate = self.tgn.api.config()
        candidate.deserialize(self.contents)
        yaml_payload = candidate.serialize(encoding='yaml')
        self.assertTrue(
            self.tgn.apply_configuration(yaml_payload, restart=False))
        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])

        self.assertTrue(
            self.tgn.apply_configuration(candidate, restart=False))
        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])

    def inline_dual_stack_configuration(self):
        # Build a candidate without replacing the currently applied model;
        # controller-rejection coverage relies on retaining that model.
        config = self.tgn.api.config()
        config.ports.add(name='p1', location='localhost:5555')
        config.ports.add(name='p2', location='localhost:5556')
        device = config.devices.add(name='dual-stack-host')
        ethernet = device.ethernets.add(name='eth1',
                                        mac='00:00:01:00:00:01')
        ethernet.connection.port_name = 'p1'
        ethernet.ipv4_addresses.add(name='v4', address='192.0.2.2',
                                    gateway='192.0.2.1', prefix=24)
        ethernet.ipv6_addresses.add(name='v6', address='2001:db8::2',
                                    gateway='2001:db8::1', prefix=64)
        flow = config.flows.add(name='f1')
        flow.tx_rx.port.tx_name = 'p1'
        flow.tx_rx.port.rx_name = 'p2'
        flow.packet.ethernet()
        flow.packet.ipv6()
        return json.loads(config.serialize())

    def test_inline_configuration_is_archived_and_resolves_dual_stack(self):
        directory = self.run_directory()
        payload = self.inline_dual_stack_configuration()

        with patch.object(implementation, 'runtime', self.easypy(directory)), \
                patch.object(self.tgn, 'start_all_protocols',
                             wraps=self.tgn.start_all_protocols) as arp, \
                patch.object(self.tgn, 'send_ns',
                             wraps=self.tgn.send_ns) as ns:
            self.assertTrue(self.tgn.apply_configuration(payload, wait_time=0))

        self.assertEqual(self.tgn.get_traffic_stream_names(), ['f1'])
        arp.assert_called_once_with(wait_time=0)
        ns.assert_called_once_with(wait_time=0)
        archived = os.path.join(directory, 'otg1_otg_configuration.json')
        with open(archived) as handle:
            self.assertEqual(json.load(handle), payload)

    def test_rejected_inline_input_is_archived_without_stopping_traffic(self):
        directory = self.run_directory()
        original = self.add_flow()
        self.tgn.start_traffic(wait_time=0)

        with patch.object(implementation, 'runtime', self.easypy(directory)), \
                patch.object(self.tgn.translation_engine, 'stop_traffic') as stop:
            with self.assertRaises(GenieTgnError):
                self.tgn.apply_configuration('- not\n- a mapping\n', wait_time=0)

        self.assertEqual(self.tgn.get_traffic_stream_names(), [original])
        stop.assert_not_called()
        self.assertTrue(os.path.exists(
            os.path.join(directory, 'otg1_otg_configuration.json')))

    def test_controller_rejection_keeps_the_previous_configuration_in_memory(self):
        original = self.add_flow()
        self.tgn.start_traffic(wait_time=0)
        payload = self.inline_dual_stack_configuration()

        with patch.object(self.tgn.api, 'set_config',
                          side_effect=RuntimeError('controller says no')):
            with self.assertRaisesRegex(GenieTgnError, 'controller says no'):
                self.tgn.apply_configuration(payload, wait_time=0)

        self.assertEqual(self.tgn.get_traffic_stream_names(), [original])


class TestPacketCapture(OtgTestCase):
    '''Captures are started and stopped per port and fetched as a file.'''

    def setUp(self):
        super().setUp()
        config = self.tgn.api.config()
        config.ports.add(name='p1', location='localhost:5555')
        config.ports.add(name='p2', location='localhost:5556')
        self.tgn.set_config(config)
        self.workspace = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

    def capturing(self):
        return self.tgn.api.engine.capturing_ports()

    def test_every_port_captures_by_default(self):
        self.tgn.start_capture()
        self.assertEqual(self.capturing(), {'p1', 'p2'})

        self.tgn.stop_capture()
        self.assertEqual(self.capturing(), set())

    def test_named_ports_capture_on_their_own(self):
        self.tgn.start_capture(['p1'])
        self.assertEqual(self.capturing(), {'p1'})

        self.tgn.stop_capture(['p1'])
        self.assertEqual(self.capturing(), set())

    def test_a_capture_is_written_to_the_given_path(self):
        path = os.path.join(self.workspace, 'p1.pcap')
        self.assertEqual(self.tgn.save_capture('p1', path), path)
        with open(path, 'rb') as capture:
            # The simulator records no packets, so this is a pcap file header
            # and nothing else.
            self.assertEqual(capture.read(), mock.PCAP_FILE_HEADER)

    def test_a_capture_defaults_to_the_run_directory(self):
        with patch.object(implementation, 'runtime',
                          SimpleNamespace(directory=self.workspace,
                                          runinfo=True)):
            path = self.tgn.save_capture('p2')
        self.assertEqual(path,
                         os.path.join(self.workspace, 'otg1-p2.pcap'))
        self.assertTrue(os.path.exists(path))

    def test_capturing_an_unknown_port_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.save_capture('p3', os.path.join(self.workspace, 'x.pcap'))


class TestGeneratedArtifactPaths(OtgTestCase):
    '''Generated names stay in their destination; explicit paths stay explicit.'''

    def setUp(self):
        super().setUp()
        self.workspace = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.directory = os.path.join(self.workspace, 'runinfo')
        os.mkdir(self.directory)
        self.runtime = SimpleNamespace(directory=self.directory, runinfo=True)
        config = self.tgn.api.config()
        for name in ('p1', 'Ethernet1/1', 'Ethernet1%2F1', '../outside',
                     r'..\outside'):
            config.ports.add(name=name, location='mock')
        self.tgn.set_config(config)

    def assert_capture(self, path, directory, filename):
        self.assertEqual(path, os.path.join(directory, filename))
        self.assertEqual(os.path.dirname(os.path.realpath(path)),
                         os.path.realpath(directory))
        with open(path, 'rb') as capture:
            self.assertEqual(capture.read(), mock.PCAP_FILE_HEADER)

    def escaping_symlink(self, filename):
        target = os.path.join(self.workspace, 'outside')
        with open(target, 'wb') as existing:
            existing.write(b'keep existing contents')
        os.symlink(target, os.path.join(self.directory, filename))
        return target

    def assert_not_overwritten(self, target):
        with open(target, 'rb') as existing:
            self.assertEqual(existing.read(), b'keep existing contents')

    def test_archive_encodes_device_names(self):
        for name, encoded in (('../outside', '..%2Foutside'),
                              (r'..\outside', '..%5Coutside'),
                              ('lab/device', 'lab%2Fdevice')):
            with self.subTest(name=name), \
                    patch.object(self.dev, 'name', name), \
                    patch.object(implementation, 'runtime', self.runtime):
                path = self.tgn._archive_configuration('source.json', '{}')
                self.assertEqual(path, os.path.join(
                    self.directory, encoded + '_source.json'))
                with open(path) as archived:
                    self.assertEqual(archived.read(), '{}')

    def test_archive_refuses_an_escaping_symlink_without_failing(self):
        target = self.escaping_symlink('otg1_source.json')
        with patch.object(implementation, 'runtime', self.runtime), \
                self.assertLogs(implementation.log, level='WARNING'):
            self.assertIsNone(
                self.tgn._archive_configuration('source.json', '{}'))
        self.assert_not_overwritten(target)

    def test_default_capture_encodes_traversal_in_device_name(self):
        with patch.object(self.dev, 'name', '../outside'), \
                patch.object(implementation, 'runtime', self.runtime):
            path = self.tgn.save_capture('p1')
        self.assert_capture(path, self.directory, '..%2Foutside-p1.pcap')

    def test_default_capture_encodes_an_absolute_device_name(self):
        name = os.path.join(self.workspace, 'absolute')
        with patch.object(self.dev, 'name', name), \
                patch.object(implementation, 'runtime', self.runtime):
            path = self.tgn.save_capture('p1')
        self.assertEqual(os.path.dirname(os.path.realpath(path)),
                         os.path.realpath(self.directory))
        self.assertFalse(os.path.exists(name + '-p1.pcap'))

    def test_default_capture_encodes_port_separators(self):
        for port, encoded in (('Ethernet1/1', 'Ethernet1%2F1'),
                              (r'..\outside', '..%5Coutside')):
            with self.subTest(port=port), \
                    patch.object(implementation, 'runtime', self.runtime):
                path = self.tgn.save_capture(port)
                self.assert_capture(path, self.directory,
                                    'otg1-' + encoded + '.pcap')

    def test_encoded_port_names_do_not_overwrite_literal_percent_names(self):
        with patch.object(implementation, 'runtime', self.runtime):
            first = self.tgn.save_capture('Ethernet1/1')
            second = self.tgn.save_capture('Ethernet1%2F1')
        self.assert_capture(first, self.directory,
                            'otg1-Ethernet1%2F1.pcap')
        self.assert_capture(second, self.directory,
                            'otg1-Ethernet1%252F1.pcap')

    def test_default_capture_refuses_an_escaping_symlink(self):
        target = self.escaping_symlink('otg1-p1.pcap')
        with patch.object(implementation, 'runtime', self.runtime), \
                self.assertRaises(OSError):
            self.tgn.save_capture('p1')
        self.assert_not_overwritten(target)

    def test_compatibility_capture_encodes_port_traversal(self):
        with patch.object(implementation, 'runtime', self.runtime):
            path = self.tgn.save_packet_capture_file(
                '../outside', 'data', 'run')
        self.assert_capture(path, self.directory,
                            '..%2Foutside_HW_run.pcap')

    def test_compatibility_capture_encodes_the_base_filename(self):
        with patch.object(implementation, 'runtime', self.runtime):
            path = self.tgn.save_packet_capture_file(
                'p1', 'control', '../nested/run')
        self.assert_capture(path, self.directory,
                            'p1_SW_..%2Fnested%2Frun.pcap')

    def test_compatibility_capture_refuses_an_escaping_symlink(self):
        target = self.escaping_symlink('p1_HW_run.pcap')
        with patch.object(implementation, 'runtime', self.runtime), \
                self.assertRaises(OSError):
            self.tgn.save_packet_capture_file('p1', 'data', 'run')
        self.assert_not_overwritten(target)

    def test_compatibility_capture_accepts_a_caller_selected_directory(self):
        with patch.object(implementation, 'runtime', self.runtime):
            path = self.tgn.save_packet_capture_file(
                'Ethernet1/1', 'data', 'run', directory=self.workspace)
        self.assert_capture(path, self.workspace,
                            'Ethernet1%2F1_HW_run.pcap')

    def test_explicit_capture_path_is_preserved_outside_run_directory(self):
        path = os.path.join(self.workspace, 'caller-selected.pcap')
        with patch.object(implementation, 'runtime', self.runtime):
            self.assertEqual(self.tgn.save_capture('Ethernet1/1', path), path)
        self.assert_capture(path, self.workspace, 'caller-selected.pcap')

    def test_explicit_configuration_path_is_preserved(self):
        path = os.path.join(self.workspace, 'caller-selected.json')
        with patch.object(implementation, 'runtime', self.runtime):
            self.assertEqual(self.tgn.save_configuration(path), path)
        with open(path) as saved:
            self.assertEqual(json.load(saved), json.loads(
                self.tgn.config.serialize()))

    def test_a_symlink_to_the_run_directory_is_supported(self):
        alias = os.path.join(self.workspace, 'runinfo-link')
        os.symlink(self.directory, alias)
        with patch.object(implementation, 'runtime',
                          SimpleNamespace(directory=alias, runinfo=True)):
            path = self.tgn.save_capture('p1')
        self.assert_capture(path, alias, 'otg1-p1.pcap')

    def export_capture(self, filename='ixia.pcap'):
        source = self.tgn.save_capture(
            'p1', os.path.join(self.workspace, 'source.pcap'))
        with patch.object(implementation, 'runtime', self.runtime):
            return self.tgn.export_packet_capture_file(source, filename)

    def test_export_encodes_parent_directory_segments(self):
        for name, encoded in (('../outside.pcap', '..%2Foutside.pcap'),
                              ('nested/capture.pcap',
                               'nested%2Fcapture.pcap'),
                              (r'..\outside.pcap', '..%5Coutside.pcap')):
            with self.subTest(name=name):
                path = self.export_capture(name)
                self.assert_capture(path, self.directory, encoded)
        self.assertFalse(os.path.exists(
            os.path.join(self.workspace, 'outside.pcap')))

    def test_export_encodes_an_absolute_filename(self):
        name = os.path.join(self.workspace, 'absolute.pcap')
        path = self.export_capture(name)
        self.assert_capture(path, self.directory, name.replace('/', '%2F'))
        self.assertFalse(os.path.exists(name))

    def test_export_refuses_an_escaping_symlink(self):
        target = self.escaping_symlink('ixia.pcap')
        with self.assertRaises(OSError):
            self.export_capture()
        self.assert_not_overwritten(target)

    def test_export_keeps_the_default_filename(self):
        path = self.export_capture()
        self.assert_capture(path, self.directory, 'ixia.pcap')

    def test_export_of_the_source_to_itself_is_supported(self):
        path = self.tgn.save_capture(
            'p1', os.path.join(self.directory, 'source.pcap'))
        with patch.object(implementation, 'runtime', self.runtime), \
                patch.object(implementation, 'copyfile') as copy:
            self.assertEqual(self.tgn.export_packet_capture_file(
                path, 'source.pcap'), path)
        copy.assert_not_called()
        self.assert_capture(path, self.directory, 'source.pcap')

    def statistics_snapshot(self, filename, directory=None):
        with patch.object(implementation, 'runtime', self.runtime):
            return self.tgn.save_statistics_snapshot_csv(
                'Port Statistics', csv_windows_path=directory,
                csv_file_name=filename)

    def assert_snapshot(self, path, directory, filename):
        self.assertEqual(path, os.path.join(directory, filename))
        self.assertEqual(os.path.dirname(os.path.realpath(path)),
                         os.path.realpath(directory))
        with open(path) as snapshot:
            self.assertIn('p1', snapshot.read())

    def test_snapshot_encodes_parent_directory_segments(self):
        for name, encoded in (('../snapshot', '..%2Fsnapshot.csv'),
                              ('nested/snapshot', 'nested%2Fsnapshot.csv'),
                              (r'..\snapshot', '..%5Csnapshot.csv')):
            with self.subTest(name=name):
                path = self.statistics_snapshot(name)
                self.assert_snapshot(path, self.directory, encoded)
        self.assertFalse(os.path.exists(
            os.path.join(self.workspace, 'snapshot.csv')))

    def test_snapshot_encodes_an_absolute_filename(self):
        name = os.path.join(self.workspace, 'absolute')
        path = self.statistics_snapshot(name)
        self.assert_snapshot(path, self.directory,
                             name.replace('/', '%2F') + '.csv')
        self.assertFalse(os.path.exists(name + '.csv'))

    def test_snapshot_refuses_an_escaping_symlink(self):
        target = self.escaping_symlink('snapshot.csv')
        with self.assertRaises(OSError):
            self.statistics_snapshot('snapshot')
        self.assert_not_overwritten(target)

    def test_snapshot_accepts_a_caller_selected_directory(self):
        directory = os.path.join(self.workspace, 'selected')
        os.mkdir(directory)
        path = self.statistics_snapshot('../snapshot', directory)
        self.assert_snapshot(path, directory, '..%2Fsnapshot.csv')
        self.assertFalse(os.path.exists(
            os.path.join(self.workspace, 'snapshot.csv')))

    def test_export_and_snapshot_support_a_symlinked_run_directory(self):
        alias = os.path.join(self.workspace, 'runinfo-link')
        os.symlink(self.directory, alias)
        self.runtime.directory = alias
        self.assert_capture(self.export_capture(), alias, 'ixia.pcap')
        self.assert_snapshot(self.statistics_snapshot('snapshot'), alias,
                             'snapshot.csv')


class TestRemoteCapture(unittest.TestCase):
    '''A capture fetched from a remote controller keeps its bytes.'''

    # A little-endian pcap header; d4 c3 is not valid UTF-8.
    PCAP = bytes.fromhex('d4c3b2a1020004000000000000000000ffff000001000000')

    def setUp(self):
        self.api = mock.MockOtgApi(location='http://localhost:8443',
                                   transport='http')
        patcher = patch.object(mock.urllib.request, 'urlopen')
        self.urlopen = patcher.start()
        self.addCleanup(patcher.stop)

    def respond(self, body):
        response = self.urlopen.return_value.__enter__.return_value
        response.read.return_value = body

    def test_a_remote_capture_is_returned_as_bytes(self):
        self.respond(self.PCAP)
        request = self.api.capture_request()
        request.port_name = 'p1'
        self.assertEqual(self.api.get_capture(request), self.PCAP)
        sent = self.urlopen.call_args[0][0]
        self.assertEqual(sent.full_url,
                         'http://localhost:8443/results/capture')
        self.assertEqual(json.loads(sent.data), {'port_name': 'p1'})

    def test_other_remote_responses_are_still_decoded(self):
        self.respond(b'{"status": "success"}')
        self.assertEqual(
            self.api.set_control_state(self.api.control_state()),
            {'status': 'success'})


class TestEmulatedBgp(unittest.TestCase):
    '''The BGP helpers address peers by their OTG names.

    The simulator emulates no BGP, so these drive a stand-in API: what is
    under test is the request each helper builds and the response it reads.
    '''

    def setUp(self):
        self.testbed = loader.load(TESTBED)
        self.dev = self.testbed.devices.otg1
        self.tgn = self.dev.instantiate(via='tgn', alias='tgn')
        self.tgn.connect()
        self.addCleanup(self.dev.destroy)
        self.addCleanup(self.tgn.disconnect)

        self.api = Mock()
        self.requests = []
        self.api.control_state.side_effect = self.control_state
        self.api.metrics_request.side_effect = self.metrics_request
        self.api.get_metrics.side_effect = self.get_metrics
        self.api.set_control_state.side_effect = self.requests.append
        self.tgn._api = self.api

        self.peers = {'bgpv4': ['v4-peer'], 'bgpv6': ['v6-peer']}
        self.state = {'v4-peer': 'up', 'v6-peer': 'up'}
        self.end_of_rib = {'v4-peer': 1, 'v6-peer': 1}
        patcher = patch.object(type(self.tgn), '_bgp_peer_names',
                               lambda _self: dict(self.peers))
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def control_state():
        bgp = SimpleNamespace(peers=SimpleNamespace(peer_names=[], state=None))
        protocol = SimpleNamespace(BGP='bgp', bgp=bgp, choice=None)
        return SimpleNamespace(PROTOCOL='protocol', protocol=protocol,
                               choice=None)

    @staticmethod
    def metrics_request():
        return SimpleNamespace(
            choice=None,
            bgpv4=SimpleNamespace(peer_names=[]),
            bgpv6=SimpleNamespace(peer_names=[]))

    def get_metrics(self, request):
        choice = request.choice
        metrics = []
        for name in getattr(request, choice).peer_names:
            metric = SimpleNamespace(
                name=name, session_state=self.state[name],
                end_of_rib_received=self.end_of_rib[name])
            metric._TYPES = ('name', 'session_state', 'end_of_rib_received')
            metrics.append(metric)
        return SimpleNamespace(**{'{}_metrics'.format(choice): metrics})

    def test_metrics_are_keyed_by_peer_name(self):
        metrics = self.tgn.get_bgp_metrics()
        self.assertEqual(sorted(metrics), ['v4-peer', 'v6-peer'])
        self.assertEqual(metrics['v4-peer']['session_state'], 'up')
        self.assertNotIn('name', metrics['v4-peer'])

    def test_a_single_peer_can_be_asked_for(self):
        self.assertEqual(list(self.tgn.get_bgp_metrics('v6-peer')),
                         ['v6-peer'])

    def test_an_unknown_peer_raises(self):
        with self.assertRaisesRegex(GenieTgnError, 'absent-peer'):
            self.tgn.get_bgp_metrics(['absent-peer'])

    def test_ixnetwork_device_metrics_are_returned_by_peer_name(self):
        peer = type('BgpV4Peer', (), {})()
        peer.name = 'v4-peer'
        self.tgn.ext = 'ixnetwork'
        self.tgn._config = SimpleNamespace(devices=[
            SimpleNamespace(name='MixedCaseDevice', peers=[peer])])
        metric = SimpleNamespace(name='mixedcasedevice', session_state='up')
        metric._TYPES = ('name', 'session_state')
        self.api.get_metrics.side_effect = None
        self.api.get_metrics.return_value = SimpleNamespace(
            bgpv4_metrics=[metric])

        self.assertEqual(self.tgn.get_bgp_metrics('v4-peer'),
                         {'v4-peer': {'session_state': 'up'}})
        request = self.api.get_metrics.call_args[0][0]
        self.assertEqual(request.bgpv4.peer_names, ['MixedCaseDevice'])

    def test_ixnetwork_metrics_refuse_ambiguous_device_groups(self):
        peers = []
        for name in ('v4-peer', 'another-peer'):
            peer = type('BgpV4Peer', (), {})()
            peer.name = name
            peers.append(peer)
        self.tgn.ext = 'ixnetwork'
        self.tgn._config = SimpleNamespace(devices=[
            SimpleNamespace(name='device1', peers=peers)])
        with self.assertRaisesRegex(GenieTgnError, 'one peer'):
            self.tgn.get_bgp_metrics('v4-peer')
        self.api.get_metrics.assert_not_called()

    def test_ixnetwork_metrics_refuse_case_colliding_device_names(self):
        devices = []
        for device_name, peer_name in [('Device1', 'v4-peer'),
                                       ('device1', 'another-peer')]:
            peer = type('BgpV4Peer', (), {})()
            peer.name = peer_name
            devices.append(SimpleNamespace(name=device_name, peers=[peer]))
        self.peers['bgpv4'].append('another-peer')
        self.tgn.ext = 'ixnetwork'
        self.tgn._config = SimpleNamespace(devices=devices)
        with self.assertRaisesRegex(GenieTgnError, 'distinct'):
            self.tgn.get_bgp_metrics(['v4-peer', 'another-peer'])
        self.api.get_metrics.assert_not_called()

    def test_metrics_for_other_peers_are_not_returned(self):
        self.api.get_metrics.side_effect = None
        metric = SimpleNamespace(name='another-peer', session_state='up')
        metric._TYPES = ('name', 'session_state')
        self.api.get_metrics.return_value = SimpleNamespace(
            bgpv4_metrics=[metric])
        self.assertEqual(self.tgn.get_bgp_metrics('v4-peer'), {})

    def test_sessions_are_verified_once_they_are_up(self):
        self.assertEqual(sorted(self.tgn.verify_bgp_sessions(max_time=0)),
                         ['v4-peer', 'v6-peer'])

    def test_verification_waits_for_metrics_after_protocol_start(self):
        ready = self.tgn.get_bgp_metrics()
        with patch.object(type(self.tgn), 'get_bgp_metrics',
                          side_effect=[{}, ready]) as get_metrics:
            with patch('genie.trafficgen.otg.implementation.time.sleep'):
                self.assertEqual(self.tgn.verify_bgp_sessions(max_time=1),
                                 ready)
        self.assertEqual(get_metrics.call_count, 2)

    def test_missing_configured_peers_do_not_pass_verification(self):
        with patch.object(type(self.tgn), 'get_bgp_metrics', return_value={}):
            with self.assertRaisesRegex(GenieTgnError, 'v4-peer, v6-peer'):
                self.tgn.verify_bgp_sessions(max_time=0)

    def test_partial_metrics_do_not_pass_verification(self):
        metrics = self.tgn.get_bgp_metrics('v4-peer')
        with patch.object(type(self.tgn), 'get_bgp_metrics',
                          return_value=metrics):
            with self.assertRaisesRegex(GenieTgnError, 'v6-peer'):
                self.tgn.verify_bgp_sessions(max_time=0)

    def test_a_single_peer_name_is_verified(self):
        self.assertEqual(list(self.tgn.verify_bgp_sessions('v6-peer',
                                                         max_time=0)),
                         ['v6-peer'])

    def test_verification_without_configured_peers_raises(self):
        self.peers = {'bgpv4': [], 'bgpv6': []}
        with self.assertRaisesRegex(GenieTgnError, 'No BGP peers'):
            self.tgn.verify_bgp_sessions(max_time=0)

    def test_verification_times_out_naming_the_session(self):
        self.state['v6-peer'] = 'down'
        with self.assertRaisesRegex(GenieTgnError, 'v6-peer'):
            self.tgn.verify_bgp_sessions(max_time=0)

    def test_end_of_rib_is_checked_on_request(self):
        self.end_of_rib['v4-peer'] = 0
        self.tgn.verify_bgp_sessions(max_time=0)
        with self.assertRaisesRegex(GenieTgnError, 'v4-peer'):
            self.tgn.verify_bgp_sessions(check_eor=True, max_time=0)

    def test_an_invalid_state_raises(self):
        with self.assertRaises(GenieTgnError):
            self.tgn.verify_bgp_sessions(state='flapping')

    def test_peer_control_rejects_invalid_states_without_sending(self):
        for state in ('flapping', 'UP', None):
            with self.subTest(state=state):
                with self.assertRaisesRegex(GenieTgnError, 'state'):
                    self.tgn.set_bgp_peer_state(['v4-peer'], state)
        self.api.set_control_state.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_peer_control_rejects_unknown_names_without_sending(self):
        for peers in (['absent-peer'], ['v4-peer', 'absent-peer']):
            with self.subTest(peers=peers):
                with self.assertRaisesRegex(GenieTgnError, 'absent-peer'):
                    self.tgn.set_bgp_peer_state(peers, 'down')
        self.api.set_control_state.assert_not_called()
        self.assertEqual(self.requests, [])

    def test_a_single_peer_name_can_be_controlled(self):
        self.assertEqual(self.tgn.set_bgp_peer_state('v6-peer', 'down'),
                         ['v6-peer'])
        self.assertEqual(self.requests[-1].protocol.bgp.peers.peer_names,
                         ['v6-peer'])

    def test_peers_are_brought_down_by_name(self):
        self.assertEqual(self.tgn.set_bgp_peer_state(['v4-peer'], 'down'),
                         ['v4-peer'])
        control = self.requests[-1]
        self.assertEqual(control.choice, 'protocol')
        self.assertEqual(control.protocol.choice, 'bgp')
        self.assertEqual(control.protocol.bgp.peers.peer_names, ['v4-peer'])
        self.assertEqual(control.protocol.bgp.peers.state, 'down')

    def test_every_peer_is_acted_on_by_default(self):
        self.assertEqual(self.tgn.set_bgp_peer_state(),
                         ['v4-peer', 'v6-peer'])

    def test_ixnetwork_does_not_claim_an_ignored_peer_state_change(self):
        self.tgn.ext = 'ixnetwork'
        with self.assertRaisesRegex(GenieTgnError, 'does not implement BGP'):
            self.tgn.set_bgp_peer_state(['v4-peer'], 'down')
        self.api.set_control_state.assert_not_called()

    def test_a_configuration_without_peers_raises(self):
        self.peers = {'bgpv4': [], 'bgpv6': []}
        with self.assertRaises(GenieTgnError):
            self.tgn.set_bgp_peer_state()

    def test_a_controller_failure_is_reported(self):
        self.api.set_control_state.side_effect = RuntimeError('no route')
        with self.assertRaisesRegex(GenieTgnError, 'no route'):
            self.tgn.set_bgp_peer_state(['v4-peer'], 'down')


class TestEmulatedBgpNeedsAController(OtgTestCase):
    '''The simulator emulates no BGP, and says so rather than failing oddly.'''

    def test_metrics_report_the_unsupported_transport(self):
        with self.assertRaisesRegex(GenieTgnError, "transport='mock'"):
            self.tgn.get_bgp_metrics()

    def test_peer_state_reports_the_unsupported_transport(self):
        with self.assertRaisesRegex(GenieTgnError, "transport='mock'"):
            self.tgn.set_bgp_peer_state()



class TestMockFlowAttributeSerialization(unittest.TestCase):
    '''Rate and size serialization honor the selected SDK encoding.'''

    @staticmethod
    def attributes():
        rate = mock.FlowRate()
        rate.mbps = 10
        size = mock.FlowSize()
        size.fixed = 256
        return ((rate, {'choice': 'mbps', 'mbps': 10}),
                (size, {'choice': 'fixed', 'fixed': 256}))

    def test_default_and_explicit_dict_encoding_are_preserved(self):
        for attribute, expected in self.attributes():
            with self.subTest(attribute=type(attribute).__name__):
                self.assertEqual(attribute.serialize(), expected)
                self.assertEqual(attribute.serialize(encoding='dict'),
                                 expected)

    def test_json_encoding_returns_json_text(self):
        for attribute, expected in self.attributes():
            with self.subTest(attribute=type(attribute).__name__):
                encoded = attribute.serialize(encoding='json')
                self.assertIsInstance(encoded, str)
                self.assertEqual(json.loads(encoded), expected)

    def test_yaml_encoding_returns_yaml_text(self):
        for attribute, expected in self.attributes():
            with self.subTest(attribute=type(attribute).__name__):
                encoded = attribute.serialize(encoding='yaml')
                self.assertIsInstance(encoded, str)
                self.assertEqual(yaml.safe_load(encoded), expected)

    def test_unsupported_encoding_is_rejected(self):
        for attribute, _ in self.attributes():
            with self.subTest(attribute=type(attribute).__name__):
                with self.assertRaisesRegex(NotImplementedError,
                                            'Encoding xml not supported'):
                    attribute.serialize(encoding='xml')

    def test_explicit_encodings_match_sdk_flow_attributes(self):
        try:
            import snappi
        except ImportError:
            self.skipTest('Snappi is required for SDK model compatibility')
        for attribute, _ in self.attributes():
            sdk_attribute = getattr(snappi, type(attribute).__name__)()
            if isinstance(attribute, mock.FlowRate):
                # Percentage is numeric in both models.
                attribute.percentage = 12.5
                sdk_attribute.percentage = 12.5
            else:
                sdk_attribute.fixed = 256
            for encoding in ('dict', 'json', 'yaml'):
                with self.subTest(attribute=type(attribute).__name__,
                                  encoding=encoding):
                    encoded = attribute.serialize(encoding=encoding)
                    sdk_encoded = sdk_attribute.serialize(encoding=encoding)
                    if encoding != 'dict':
                        self.assertIsInstance(encoded, str)
                        encoded = yaml.safe_load(encoded)
                        sdk_encoded = yaml.safe_load(sdk_encoded)
                    self.assertEqual(encoded, sdk_encoded)


class TestMockRateChoices(unittest.TestCase):
    """The mock retains rate choices and never substitutes stale PPS."""

    def setUp(self):
        self.api = mock.MockOtgApi()

    def config(self, choice='pps', value=1000, size=128):
        config = self.api.config()
        config.ports.add(name='p1', location='localhost:5555')
        config.ports.add(name='p2', location='localhost:5556')
        flow = config.flows.add(name='f1')
        flow.tx_rx.port.tx_name = 'p1'
        flow.tx_rx.port.rx_name = 'p2'
        flow.size.fixed = size
        setattr(flow.rate, choice, value)
        return config

    def start(self):
        state = self.api.control_state()
        state.choice = state.TRAFFIC
        state.traffic.choice = state.traffic.FLOW_TRANSMIT
        state.traffic.flow_transmit.flow_names = ['f1']
        state.traffic.flow_transmit.state = state.traffic.flow_transmit.START
        self.api.set_control_state(state)

    def metric(self):
        return self.api.get_metrics(self.api.metrics_request()).flow_metrics[0]

    def test_each_rate_choice_round_trips(self):
        for choice, value in [('pps', 321), ('percentage', .01),
                              ('bps', 1000000), ('kbps', 1000),
                              ('mbps', 10), ('gbps', 1)]:
            with self.subTest(choice=choice):
                config = self.config(choice, value)
                restored = self.api.config().deserialize(config.serialize())
                self.assertEqual(restored.flows[0].rate.to_dict(),
                                 {'choice': choice, choice: value})

    def test_active_choice_wins_over_an_inactive_pps_field(self):
        payload = json.loads(self.config().serialize())
        payload['flows'][0]['rate'] = {
            'choice': 'mbps', 'mbps': 10, 'pps': 777}
        config = self.api.config().deserialize(payload)
        self.assertEqual(config.flows[0].rate.to_dict(),
                         {'choice': 'mbps', 'mbps': 10})

    def test_invalid_active_rate_fields_are_rejected(self):
        for rate in ({'choice': 'ppss', 'ppss': 777},
                     {'choice': 'mbps'}, {'choice': 'pps', 'mbps': 10}):
            with self.subTest(rate=rate):
                payload = json.loads(self.config().serialize())
                payload['flows'][0]['rate'] = rate
                with self.assertRaisesRegex(ValueError, 'rate'):
                    self.api.config().deserialize(payload)

    def test_initial_bit_rate_drives_packet_and_byte_metrics(self):
        for choice, value, multiplier in [('bps', 1000000, 1),
                                          ('kbps', 1000, 1000),
                                          ('mbps', 10, 1000000),
                                          ('gbps', 1, 1000000000)]:
            with self.subTest(choice=choice):
                self.api = mock.MockOtgApi()
                self.api.set_config(self.config(choice, value))
                self.start()
                metric = self.metric()
                expected = value * multiplier / (128 * 8)
                self.assertAlmostEqual(metric.frames_tx_rate, expected)
                self.assertAlmostEqual(metric.frames_rx_rate, expected)
                self.assertAlmostEqual(metric.tx_rate_bytes, expected * 128)

    def test_live_bit_rate_update_changes_metrics_and_configuration(self):
        self.api.set_config(self.config())
        self.start()
        update = self.api.config_update().flows
        update.property_names = ['rate']
        update.flows.append(self.config('mbps', 10).flows[0])
        self.api.update_flows(update)
        metric = self.metric()
        self.assertEqual(metric.transmit, 'started')
        self.assertAlmostEqual(metric.frames_tx_rate, 10000000 / (128 * 8))
        self.assertEqual(self.api.get_config().flows[0].rate.to_dict(),
                         {'choice': 'mbps', 'mbps': 10})

    def test_live_update_accepts_sdk_rate_serialization(self):
        try:
            import snappi
        except ImportError:
            self.skipTest('Snappi is required for SDK model compatibility')
        self.api.set_config(self.config())
        self.start()
        flow = self.config().flows[0]
        flow.rate = snappi.FlowRate()
        flow.rate.mbps = 10
        update = self.api.config_update().flows
        update.property_names = ['rate']
        update.flows.append(flow)
        self.api.update_flows(update)
        self.assertAlmostEqual(self.metric().frames_tx_rate,
                               10000000 / (128 * 8))
        self.assertEqual(self.api.get_config().flows[0].rate.choice, 'mbps')

    def test_size_only_update_recomputes_bit_rate_pps(self):
        self.api.set_config(self.config('mbps', 10))
        self.start()
        update = self.api.config_update().flows
        update.property_names = ['size']
        # This rate is unselected and must not override the active bit rate.
        update.flows.append(self.config('percentage', 50, 256).flows[0])
        self.api.update_flows(update)
        metric = self.metric()
        self.assertAlmostEqual(metric.frames_tx_rate, 10000000 / (256 * 8))
        self.assertEqual(self.api.get_config().flows[0].rate.choice, 'mbps')
        self.assertEqual(self.api.get_config().flows[0].size.fixed, 256)

    def test_percentage_configuration_fails_before_replacing_state(self):
        config = self.config()
        self.api.set_config(config)
        previous = {name: dict(state)
                    for name, state in self.api.engine._flows.items()}
        with self.assertRaisesRegex(ValueError, 'percentage.*link speed'):
            self.api.set_config(self.config('percentage', 10))
        self.assertIs(self.api.get_config(), config)
        self.assertEqual(self.api.engine._flows, previous)

    def test_invalid_later_update_does_not_partly_change_metrics(self):
        config = self.config()
        flow = config.flows.add(name='f2')
        flow.tx_rx.port.tx_name = 'p1'
        flow.tx_rx.port.rx_name = 'p2'
        self.api.set_config(config)
        previous = {name: dict(state)
                    for name, state in self.api.engine._flows.items()}
        update = self.api.config_update().flows
        update.property_names = ['rate']
        update.flows.append(self.config('pps', 2000).flows[0])
        invalid = self.config('percentage', 10).flows[0]
        invalid.name = 'f2'
        update.flows.append(invalid)
        with self.assertRaisesRegex(ValueError, 'percentage.*link speed'):
            self.api.update_flows(update)
        self.assertEqual(self.api.engine._flows, previous)
        self.assertEqual(self.api.get_config().flows[0].rate.pps, 1000)

    def test_live_rate_reduction_preserves_accumulated_counters(self):
        self.api.set_config(self.config('pps', 1000))
        self.start()
        with patch.object(mock.time, 'time', return_value=100):
            self.api.engine._flows['f1']['start_time'] = 90
            before = self.metric()
            update = self.api.config_update().flows
            update.property_names = ['rate']
            update.flows.append(self.config('mbps', 1).flows[0])
            self.api.update_flows(update)
            after = self.metric()
        self.assertGreaterEqual(after.frames_tx, before.frames_tx)
        self.assertGreaterEqual(after.bytes_tx, before.bytes_tx)
        self.assertEqual(after.transmit, 'started')


if __name__ == '__main__':
    unittest.main()
