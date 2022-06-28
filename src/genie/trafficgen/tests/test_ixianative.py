import os

from prettytable import PrettyTable

from pyats.topology import loader

import unittest
from unittest.mock import Mock
try:
    from IxNetwork import IxNet, IxNetError
except ImportError as e:
    raise ImportError("IxNetwork package is not installed in virtual env - "
                      "https://pypi.org/project/IxNetwork/") from e

from genie.harness.exceptions import GenieTgnError


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

    def test_check_traffic_loss(self):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia7
        dev.instantiate()
        dev.default.ixNet = Mock()

        mock_traffic_table = PrettyTable()
        mock_stream_names = ["Stream1", "Stream3"]

        mock_traffic_table.field_names = [
            "Stream", "Tx Frames", "Rx Frames", "Frames Delta", "Loss %", "Tx Frame Rate", "Rx Frame Rate", "Outage (seconds)"
        ]
        mock_traffic_table.add_row(
            ["Stream0", "11468 ", "11468 ", "0 ", "0", "200 ", "200 ", "3.0"],
        )

        dev.default.create_traffic_streams_table = Mock(return_value=mock_traffic_table)
        dev.default.get_traffic_stream_names = Mock(return_value=mock_stream_names)
        dev.default.get_traffic_stream_attribute = Mock(return_value='l2L3')

        # Check if Traffic Item is in table
        with self.assertRaisesRegex(GenieTgnError, "TGN-ERROR: Traffic Item doesn't exist in GENIE view."):
            dev.check_traffic_loss()

        # Reset table
        mock_traffic_table.clear()

        # No traffic data, should raise exception
        with self.assertRaisesRegex(GenieTgnError, "TGN-ERROR: No trafic data found"):
            dev.check_traffic_loss(disable_port_pair=True)

        # Populate table with proper data
        mock_traffic_table.field_names = [
            "Traffic Item", "Tx Frames", "Rx Frames", "Frames Delta", "Loss %", "Tx Frame Rate", "Rx Frame Rate", "Outage (seconds)"
        ]
        mock_traffic_table.add_rows([
            ["Stream1", "11468 ", "11468 ", "0 ", "0", "200", "200", "0.0"],
            ["Stream2", "2884 ", "2884 ", "0 ", "0", "50", "50", "0.0"],
            ["Stream3", "2884", "2659", "225", "7.802", "50", "50", "4.5"],
        ])

        # By default, source/dest port pair is expected, check for error
        with self.assertRaisesRegex(Exception, 'Invalid field name: Source/Dest Port Pair'):
            dev.check_traffic_loss()

        # Disable port pair, should pass
        dev.check_traffic_loss(disable_port_pair=True)

        # Disable specific stream
        dev.check_traffic_loss(traffic_streams=['Stream1'], disable_port_pair=True)

        # pre-check wait
        dev.check_traffic_loss(pre_check_wait=0.1, disable_port_pair=True)

        # Add traffic type check
        dev.check_traffic_loss(disable_port_pair=True, check_traffic_type=True)

        dev.default.get_traffic_stream_attribute = Mock(return_value=None)
        dev.check_traffic_loss(disable_port_pair=True, check_traffic_type=True)

        # Add data with loss
        mock_traffic_table.add_row(
            ["Stream4", "11468 ", "11468 ", "0 ", "20", "200 ", "200 ", "3.0"],
        )
        mock_stream_names.append('Stream4')

        # Check for exception on loss
        with self.assertRaisesRegex(GenieTgnError, 'TGN-ERROR: Unexpected traffic outage/loss is observed'):
            dev.check_traffic_loss(disable_port_pair=True, check_iteration=2, check_interval=0)

        # outage dict check
        stream = 'Stream4'
        outage_dict = {'traffic_streams': {stream: {}}}
        outage_dict['traffic_streams'][stream]['max_outage'] = 1
        outage_dict['traffic_streams'][stream]['loss_tolerance'] = 2
        outage_dict['traffic_streams'][stream]['rate_tolerance'] = 10

        # Check for exception on loss
        with self.assertRaisesRegex(GenieTgnError, 'TGN-ERROR: Unexpected traffic outage/loss is observed'):
            dev.check_traffic_loss(disable_port_pair=True, check_iteration=2, check_interval=0, outage_dict=outage_dict)

        # Check if exception is not raised with raise_on_loss False
        traffic_data = dev.check_traffic_loss(disable_port_pair=True, check_iteration=2, check_interval=0, raise_on_loss=False)

        # remove loss data
        mock_traffic_table.del_row(-1)

        # Add data with rate variance
        mock_traffic_table.add_row(
            ["Stream5", "11468 ", "11468 ", "0 ", "0", "200", "100", "0"],
        )
        mock_stream_names.append('Stream5')

        # Check for exception on rate variation
        with self.assertRaisesRegex(GenieTgnError, 'TGN-ERROR: Unexpected traffic outage/loss is observed'):
            dev.check_traffic_loss(disable_port_pair=True, check_iteration=2, check_interval=0)

        # remove rate variance data
        mock_traffic_table.del_row(-1)

        # Add data with loss seconds
        mock_traffic_table.add_row(
            ["Stream6", "11468 ", "11468 ", "0 ", "0", "200", "200", "3"],
        )
        mock_stream_names.append('Stream6')

        # Check for exception on loss seconds
        with self.assertRaisesRegex(GenieTgnError, 'TGN-ERROR: Unexpected traffic outage/loss is observed'):
            dev.check_traffic_loss(disable_port_pair=True, check_iteration=2, check_interval=0, max_outage=1)

        # expected data
        expected_traffic_data = [{
            "stream": {
                "Stream1": {
                    "Traffic Item": "Stream1",
                    "Tx Frames": 11468,
                    "Rx Frames": 11468,
                    "Frames Delta": 0,
                    "Loss %": 0,
                    "Tx Frame Rate": 200,
                    "Rx Frame Rate": 200,
                    "Outage (seconds)": 0.0
                },
                "Stream2": {
                    "Traffic Item": "Stream2",
                    "Tx Frames": 2884,
                    "Rx Frames": 2884,
                    "Frames Delta": 0,
                    "Loss %": 0,
                    "Tx Frame Rate": 50,
                    "Rx Frame Rate": 50,
                    "Outage (seconds)": 0.0
                },
                "Stream3": {
                    "Traffic Item": "Stream3",
                    "Tx Frames": 2884,
                    "Rx Frames": 2659,
                    "Frames Delta": 225,
                    "Loss %": 7.802,
                    "Tx Frame Rate": 50,
                    "Rx Frame Rate": 50,
                    "Outage (seconds)": 4.5
                },
                "Stream4": {
                    "Traffic Item": "Stream4",
                    "Tx Frames": 11468,
                    "Rx Frames": 11468,
                    "Frames Delta": 0,
                    "Loss %": 20,
                    "Tx Frame Rate": 200,
                    "Rx Frame Rate": 200,
                    "Outage (seconds)": 3.0
                }
            }
        }, {
            "stream": {
                "Stream1": {
                    "Traffic Item": "Stream1",
                    "Tx Frames": 11468,
                    "Rx Frames": 11468,
                    "Frames Delta": 0,
                    "Loss %": 0,
                    "Tx Frame Rate": 200,
                    "Rx Frame Rate": 200,
                    "Outage (seconds)": 0.0
                },
                "Stream2": {
                    "Traffic Item": "Stream2",
                    "Tx Frames": 2884,
                    "Rx Frames": 2884,
                    "Frames Delta": 0,
                    "Loss %": 0,
                    "Tx Frame Rate": 50,
                    "Rx Frame Rate": 50,
                    "Outage (seconds)": 0.0
                },
                "Stream3": {
                    "Traffic Item": "Stream3",
                    "Tx Frames": 2884,
                    "Rx Frames": 2659,
                    "Frames Delta": 225,
                    "Loss %": 7.802,
                    "Tx Frame Rate": 50,
                    "Rx Frame Rate": 50,
                    "Outage (seconds)": 4.5
                },
                "Stream4": {
                    "Traffic Item": "Stream4",
                    "Tx Frames": 11468,
                    "Rx Frames": 11468,
                    "Frames Delta": 0,
                    "Loss %": 20,
                    "Tx Frame Rate": 200,
                    "Rx Frame Rate": 200,
                    "Outage (seconds)": 3.0
                }
            }
        }]

        # Verify return data
        self.assertEqual(traffic_data, expected_traffic_data)


if __name__ == "__main__":
    unittest.main()
