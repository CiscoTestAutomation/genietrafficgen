import os

from pyats.topology import loader

import unittest
from unittest.mock import Mock


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
