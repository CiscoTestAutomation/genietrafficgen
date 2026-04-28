import os
import unittest
import importlib
from ipaddress import IPv4Address
from unittest.mock import Mock, patch
from pyats.topology import loader


class chassis_mock:
    State = 'ready'

class mock_session:
    State = 'ACTIVE'
    Id = 8020

class SessionMock:
    def __init__(self, *args, **kwargs):
        self.Ixnetwork = Mock()
        self.Ixnetwork._connection = Mock()
        self.Ixnetwork._connection._session = Mock()
        self.Ixnetwork._connection._read = Mock(return_value={
            'links': [
                {'rel': 'self', 'method': 'GET', 'href': '/api/v1/sessions/8020/ixnetwork/globals'}, 
                {'rel': 'meta', 'method': 'OPTIONS', 'href': '/api/v1/sessions/8020/ixnetwork/globals'}
	        ]
        })
        self.Ixnetwork.AvailableHardware = Mock()
        self.Ixnetwork.AvailableHardware.Chassis = Mock()
        self.Ixnetwork.AvailableHardware.Chassis.add = Mock(return_value=chassis_mock)
        self.Ixnetwork.AvailableHardware.Chassis.find = Mock(return_value=chassis_mock)
        self.Session = Mock()

        self.Session.find = Mock(return_value=[mock_session])
        mock_session.remove = Mock()

    def __call__(self, *args, **kwargs):
        self.called_args = args, kwargs
        return self


session_mock = SessionMock()

class TestIxiaIxNetworkRestPy(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        self.dev = tb.devices.ixia4
        self.dev.instantiate()

    @patch('ixnetwork_restpy.SessionAssistant', new=session_mock)
    def test_connect(self):
        # force module reload so the mock can catch the SessionAssistant class
        from genie.trafficgen.ixiarestpy.implementation import IxiaRestPy
        import genie.trafficgen
        importlib.reload(genie.trafficgen.ixiarestpy.implementation)

        self.assertTrue(isinstance(self.dev.default, IxiaRestPy))
        self.assertEqual(self.dev.default.via, 'tgn')
        
        self.dev.connect()
        called_args = session_mock.called_args[1]
        called_args.update(SessionName=None)
        self.assertEqual(called_args,
                         dict(IpAddress='192.0.0.1',
                              RestPort=11009,
                              UserName='test',
                              Password='test',
                              SessionName=None,
                              SessionId=None,
                              ApiKey=None,
                              ClearConfig=False,
                              LogLevel='info',
                              LogFilename='restpy.log')
        )

    def test_disconnect(self):
        with self.assertLogs(level='INFO') as log:
            self.dev.disconnect()
            self.assertIn('The session 8020 is removed', log.output[0])

    @patch('genie.trafficgen.ixiarestpy.implementation.time.sleep')
    def test_stop_all_protocols(self, mock_sleep):
        # Mock the StopAllProtocols method
        self.dev.default.ixnetwork = Mock()
        self.dev.default.ixnetwork.StopAllProtocols = Mock()

        # Test with default wait_time
        with self.assertLogs(level='INFO') as log:
            self.dev.default.stop_all_protocols()
            self.dev.default.ixnetwork.StopAllProtocols.assert_called_once()
            mock_sleep.assert_called_once_with(60)
            self.assertIn("Stopped protocols on device 'ixia4'", '\n'.join(log.output))
            self.assertIn("Waiting for  '60' seconds", '\n'.join(log.output))

        # Reset mocks
        self.dev.default.ixnetwork.StopAllProtocols.reset_mock()
        mock_sleep.reset_mock()

        # Test with custom wait_time
        with self.assertLogs(level='INFO') as log:
            self.dev.default.stop_all_protocols(wait_time=30)
            self.dev.default.ixnetwork.StopAllProtocols.assert_called_once()
            mock_sleep.assert_called_once_with(30)
            self.assertIn("Waiting for  '30' seconds", '\n'.join(log.output))

    @patch('genie.trafficgen.ixiarestpy.implementation.time.sleep')
    def test_stop_traffic(self, mock_sleep):
        self.dev.default.ixnetwork = Mock()
        self.dev.default.ixnetwork.Traffic = Mock()
        self.dev.default.ixnetwork.Traffic.Stop = Mock()

        with self.assertLogs(level='INFO') as log:
            self.dev.default.stop_traffic()

            self.dev.default.ixnetwork.Traffic.Stop.assert_called_once()

            mock_sleep.assert_called_once_with(60)

            log_output = '\n'.join(log.output)
            self.assertIn("Stopped traffic on device 'ixia4'", log_output)
            self.assertIn("Waiting for '60' seconds after stopping traffic", log_output)

        self.dev.default.ixnetwork.Traffic.Stop.reset_mock()
        mock_sleep.reset_mock()
        custom_wait = 15
        with self.assertLogs(level='INFO') as log:
            self.dev.default.stop_traffic(wait_time=custom_wait)
            self.dev.default.ixnetwork.Traffic.Stop.assert_called_once()
            # Verify sleep was called with custom value
            mock_sleep.assert_called_once_with(custom_wait)

            # Verify logs reflect custom time
            log_output = '\n'.join(log.output)
            self.assertIn(f"Waiting for '{custom_wait}' seconds after stopping traffic", log_output)
