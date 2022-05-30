import os

from pyats.topology import loader

import unittest
from unittest.mock import Mock
try:
    from IxNetwork import IxNet, IxNetError
except ImportError as e:
    raise ImportError("IxNetwork package is not installed in virtual env - "
                      "https://pypi.org/project/IxNetwork/") from e


class TestIxiaIxNative(unittest.TestCase):

    def test_connect_assign_ports_multichassis(self):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia5
        dev.instantiate()
        ixnet_mock = dev.default.ixNet = Mock()
        ixnet_mock.connect = Mock(return_value=True)
        ixnet_mock.OK = True
        ixnet_mock.getList = Mock(return_value=[])
        ixnet_mock.getRoot = Mock(return_value='root')
        self.assertEqual(dev.default.via, 'tgn')
        dev.connect()
        dev.assign_ixia_ports(wait_time=1)
        ixnet_mock.execute.assert_called_with(
            'assignPorts',
            [
                ['1.1.1.1', '1', '1'],
                ['1.1.1.1', '1', '2'],
                ['2.2.2.2', '2', '1'],
                ['2.2.2.2', '2', '2']
            ],
            [], [], True)

    def test_connect_assign_ports(self):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia6
        dev.instantiate()
        ixnet_mock = dev.default.ixNet = Mock()
        ixnet_mock.connect = Mock(return_value=True)
        ixnet_mock.OK = True
        ixnet_mock.getList = Mock(return_value=[])
        ixnet_mock.getRoot = Mock(return_value='root')
        self.assertEqual(dev.default.via, 'tgn')
        dev.connect()
        dev.assign_ixia_ports(wait_time=1)
        ixnet_mock.execute.assert_called_with(
            'assignPorts',
            [
                ['1.1.1.1', '1', '1'],
                ['1.1.1.1', '1', '2'],
            ],
            [], [], True)

    def test_connect_with_credentials(self):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia7
        dev.instantiate()
        ixnet_mock = dev.default.ixNet = Mock()
        ixnet_mock.connect = Mock(return_value=True)
        ixnet_mock.getApiKey = Mock(return_value='abc')
        ixnet_mock.OK = True
        dev.connect()
        ixnet_mock.connect.assert_called_with(
            '192.0.0.1', '-port', 8012, '-version', '9.00', '-setAttribute', 'strict',
            '-apiKey', 'abc', '-closeServerOnDisconnect', 1, '-setAttribute',
            'strict')

    def test_connect_with_credentials_getApiKey_raises_IxNetError(self):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia7
        dev.instantiate()
        ixnet_mock = dev.default.ixNet = Mock()
        ixnet_mock.connect = Mock(return_value=True)
        ixnet_mock.getApiKey = Mock(side_effect=IxNetError())
        ixnet_mock.OK = True
        dev.connect()
        ixnet_mock.connect.assert_called_with('192.0.0.1', '-port', 8012, '-version', '9.00', '-setAttribute', 'strict')
