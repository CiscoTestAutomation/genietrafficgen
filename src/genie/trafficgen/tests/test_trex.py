import os
import unittest
from unittest.mock import Mock

from prettytable import PrettyTable
from pyats.topology import loader


class TestTrex(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.trex1
        dev.instantiate()
        cls.dev = dev

    def test_configure_dhcpv6_request(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.configure_dhcpv6_request(interface=0, src_mac="de:ad:be:ef:00:00", requested_ip="3001::30")
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)

    def test_configure_dhcpv6_reply(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.configure_dhcpv6_reply(interface=0, src_mac="de:ad:be:ef:00:00", src_ip="3001::29", assigned_ip="3001::30", lease_time=3600)
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)

    def test_create_traffic_statistics_table_empty(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_stats = Mock(return_value={})
        expected = PrettyTable()
        expected.field_names = ['Port', 'Tx/Rx', 'Packet Bit Rate',
                                'Packet Byte Count',
                                'Packet Count', 'Packet Rate',
                                'Total_pkt_bytes', 'Total Packet Rate',
                                'Control Packet Byte Count', 'Control Packet Count',
                                'Total Packets']

        #Act
        result = dev.create_traffic_statistics_table()

        #Assert
        self.assertEqual(expected.get_string(), result.get_string())

    def test_create_traffic_statistics_table(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_stats = Mock(return_value=
            {0:
                {'aggregate':
                    {'tx':
                        {'pkt_bit_rate': 1, 'pkt_byte_count': 1, 'pkt_count': 1, 'pkt_rate': 1,
                        'total_pkt_rate': 1, 'ctl_pkt_byte_count': 1, 'ctl_pkt_count': 1,
                        'total_pkt_bytes': 1, 'total_pkts': 1},
                    'rx':
                        {'pkt_bit_rate': 1, 'pkt_byte_count': 1, 'pkt_count': 1, 'pkt_rate': 1,
                            'total_pkt_rate': 1, 'ctl_pkt_byte_count': 1, 'ctl_pkt_count': 1,
                            'total_pkt_bytes': 1, 'total_pkts': 1}
                    }
                }
            })

        expected = PrettyTable()
        expected.field_names = ['Port', 'Tx/Rx', 'Packet Bit Rate',
                                'Packet Byte Count',
                                'Packet Count', 'Packet Rate',
                                'Total_pkt_bytes', 'Total Packet Rate',
                                'Control Packet Byte Count', 'Control Packet Count',
                                'Total Packets']

        for direction in ['Tx', "Rx"]:
            data = [1]*len(expected.field_names)
            data[0] = 0
            data[1] = direction
            expected.add_row(data)

        #Act
        result = dev.create_traffic_statistics_table()

        #Assert
        self.assertEqual(expected.get_string(), result.get_string())