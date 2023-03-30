import os
import unittest
from unittest.mock import Mock

from prettytable import PrettyTable
from pyats.topology import loader

from unicon.mock.mock_device import MockDeviceSSHWrapper


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

    def test_configure_na(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.configure_na(
            interface=0, mac_src="de:ad:be:ef:00:00", ip_src="3001::29", ip_dst="3001::30",
            icmp_nd_target_mode='increment', icmp_nd_target_step=1, icmp_nd_target_count=100,
            icmp_nd_opt_dst_lladr_mode='increment', icmp_nd_opt_dst_lladr_step=1, icmp_nd_opt_dst_lladr_count=100
        )
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)

    def test_configure_garp(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.configure_garp(
            port=0, mac_src="de:ad:be:ef:00:00", ip="3001::29",
            arp_src_hw_mode='increment', arp_src_hw_step=1, arp_src_hw_count=100,
            arp_psrc_mode='increment', arp_psrc_step=1, arp_psrc_count=100
        )
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

    def test_clear_traffic(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        expected = False
        #Act
        dev.clear_traffic()
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)

    def test_enable_subinterface_emulation(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        status = Mock()
        status.handle = 1
        dev._trex.emulation_subinterface_control = Mock(return_value=status)
        expected = 1
        #Act
        result = dev.enable_subinterface_emulation(port=0, ip="3001::29", mac="de:ad:be:ef:00:00", count=100)
        #Assert
        self.assertEqual(expected, result)

    def test_disable_all_subinterface_emulation(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_subinterface_control = Mock(return_value=None)
        expected = None
        #Act
        result = dev.disable_all_subinterface_emulation(port=0)
        #Assert
        self.assertEqual(expected, result)

    def test_dhcpv4_emulator_client(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.add_dhcpv4_emulator_client(interface=0, vlan_id='105')
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)
        
    def test_dhcpv4_emulator_client_vlan_client(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.add_dhcpv4_emulator_client(interface=0, vlan_id='53', vlan_id_step=0, num_clients=1)
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)
        
        

    def test_dhcpv6_emulator_client(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True
        #Act
        dev.add_dhcpv6_emulator_client(interface=0, vlan_id='105')
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)

    def test_verify_dhcp_client_binding(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_stats = Mock(return_value=
            {'session':
                {0:
                    {'acks_received': 0,
                     'dhcp_group': '33b93e79-0a8c-4de6-b9d8-7a458c82ae36',
                     'discovers_sent': 0,
                     'ip_address': '2001:111::b486:a046:1ae0:cfee',
                     'lease_time': 0,
                     'nacks_received': 0,
                     'offers_received': 0,
                     'port_handle': 0,
                     'releases_sent': 0,
                     'requests_sent': 0,
                     'session_name': 'aa:aa:aa:aa:aa:aa',
                     'currently_attempting': 0,
                     'currently_idle': 0,
                     'currently_bound': 1
                    }
                },
                'group':
                   {'33b93e79-0a8c-4de6-b9d8-7a458c82ae36':
                           {'currently_attempting': 0,
                            'currently_idle': 0,
                            'currently_bound': 1,
                            'bound_renewed': 0,
                            'total_attempted': 0,
                            'total_bound': 0,
                            'total_failed': 0,
                            'discover_tx_count': 0,
                            'request_tx_count': 0,
                            'release_tx_count': 0,
                            'ack_rx_count': 0,
                            'nak_rx_count': 0,
                            'offer_rx_count': 0
                            }
                    }
            })
        expected = True
        #Act
        result = dev.verify_dhcp_client_binding(interface=0)
        #Assert
        self.assertEqual(expected, result)

    def test_get_dhcpv4_binding_address(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_stats = Mock(return_value=
            {'session':
                {0:
                    {'acks_received': 0,
                     'dhcp_group': '33b93e79-0a8c-4de6-b9d8-7a458c82ae36',
                     'discovers_sent': 0,
                     'ip_address': '192.168.105.1',
                     'lease_time': 0,
                     'nacks_received': 0,
                     'offers_received': 0,
                     'port_handle': 0,
                     'releases_sent': 0,
                     'requests_sent': 0,
                     'session_name': 'aa:aa:aa:aa:aa:aa',
                     'currently_attempting': 0,
                     'currently_idle': 0,
                     'currently_bound': 1
                    }
                },
                'group':
                   {'33b93e79-0a8c-4de6-b9d8-7a458c82ae36':
                           {'currently_attempting': 0,
                            'currently_idle': 0,
                            'currently_bound': 1,
                            'bound_renewed': 0,
                            'total_attempted': 0,
                            'total_bound': 0,
                            'total_failed': 0,
                            'discover_tx_count': 0,
                            'request_tx_count': 0,
                            'release_tx_count': 0,
                            'ack_rx_count': 0,
                            'nak_rx_count': 0,
                            'offer_rx_count': 0
                            }
                    }
            })
        expected = '192.168.105.1'
        #Act
        result = dev.get_dhcpv4_binding_address(interface=0)
        #Assert
        self.assertEqual(expected, result)

    def test_get_dhcpv6_binding_address(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_stats = Mock(return_value=
            {'session':
                {0:
                    {'acks_received': 0,
                     'dhcp_group': '33b93e79-0a8c-4de6-b9d8-7a458c82ae36',
                     'discovers_sent': 0,
                     'ip_address': '2001:111::b486:a046:1ae0:cfee',
                     'lease_time': 0,
                     'nacks_received': 0,
                     'offers_received': 0,
                     'port_handle': 0,
                     'releases_sent': 0,
                     'requests_sent': 0,
                     'session_name': 'aa:aa:aa:aa:aa:aa',
                     'currently_attempting': 0,
                     'currently_idle': 0,
                     'currently_bound': 1
                    }
                },
                'group':
                   {'33b93e79-0a8c-4de6-b9d8-7a458c82ae36':
                           {'currently_attempting': 0,
                            'currently_idle': 0,
                            'currently_bound': 1,
                            'bound_renewed': 0,
                            'total_attempted': 0,
                            'total_bound': 0,
                            'total_failed': 0,
                            'discover_tx_count': 0,
                            'request_tx_count': 0,
                            'release_tx_count': 0,
                            'ack_rx_count': 0,
                            'nak_rx_count': 0,
                            'offer_rx_count': 0
                            }
                    }
            })
        expected = '2001:111::b486:a046:1ae0:cfee'
        #Act
        result = dev.get_dhcpv6_binding_address(interface=0)
        #Assert
        self.assertEqual(expected, result)

    def test_reset_dhcp_session_config(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={'handle': None})
        expected = True
        #Act
        dev.reset_dhcp_session_config(interface=1)
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result) 

    def test_abort_dhcp_devx_session(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={})
        expected = False
        #Act
        dev.abort_dhcp_devx_session(interface=1)
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)  

    def test_generate_dhcp_session_handle(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_config = Mock(return_value={'handle': '880ec248-9d18-4305-b120-9f316bd58c92'})
        expected = '880ec248-9d18-4305-b120-9f316bd58c92'
        #Act
        dev.generate_dhcp_session_handle(interface=1)
        result = dev.generate_dhcp_session_handle(interface=1)
        #Assert
        self.assertEqual(expected, result)     
    

    def test_add_dhcp_emulator_bvm_client(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_group_config = Mock(return_value={'handle': '880ec248-9d18-4305-b120-9f316bd58c92'})
        expected = '880ec248-9d18-4305-b120-9f316bd58c92'
        #Act
        result = dev.add_dhcp_emulator_bvm_client (session_handle='handle')
        #Assert
        self.assertEqual(expected, result)
    
    def test_bind_dhcp_clients(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={})
        expected = False
        #Act
        dev.bind_dhcp_clients(interface=1)
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)        
 

    def test_verify_num_dhcp_clients_binding(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_stats = Mock(return_value=
            {'session':
                {0:
                    {'acks_received': 0,
                     'dhcp_group': 'handle',
                     'discovers_sent': 0,
                     'ip_address': '192.168.105.1',
                     'lease_time': 0,
                     'nacks_received': 0,
                     'offers_received': 0,
                     'port_handle': 0,
                     'releases_sent': 0,
                     'requests_sent': 0,
                     'session_name': 'aa:aa:aa:aa:aa:aa',
                     'currently_attempting': 0,
                     'currently_idle': 0,
                     'currently_bound': 1
                    }
                },
                'group':
                   {'handle':
                           {'currently_attempting': 0,
                            'currently_idle': 0,
                            'currently_bound': 1,
                            'bound_renewed': 0,
                            'total_attempted': 0,
                            'total_bound': 0,
                            'total_failed': 0,
                            'discover_tx_count': 0,
                            'request_tx_count': 0,
                            'release_tx_count': 0,
                            'ack_rx_count': 0,
                            'nak_rx_count': 0,
                            'offer_rx_count': 0
                            }
                    }
            })
        
        expected = True
        #Act
        result=dev.verify_num_dhcp_clients_binding(interface=1,handle='handle')
        #Assert
        self.assertEqual(expected, result)
    
    def test_get_dhcp_client_ip_mac_details(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_stats = Mock(return_value=
            {'session': 
               {0:
                    {'acks_received': 0,
                     'dhcp_group': '9fdbf943-17fc-4deb-9cbd-b8a051ed04f9',
                     'discovers_sent': 0,
                     'ip_address': '2001:110::895f',
                     'lease_time': 0,
                     'nacks_received': 0,
                     'offers_received': 0,
                     'port_handle': 2,
                     'releases_sent': 0,
                     'requests_sent': 0,
                     'session_name': '00:01:00:02:00:01',
                     'currently_attempting': 0,
                     'currently_idle': 0,
                     'currently_bound': 1,
                     'vlan_id': None},
                1:  
                   {'acks_received': 0,
                    'dhcp_group': '9fdbf943-17fc-4deb-9cbd-b8a051ed04f9',
                    'discovers_sent': 0,
                    'ip_address': '2001:110::9831',
                    'lease_time': 0,
                    'nacks_received': 0,
                    'offers_received': 0,
                    'port_handle': 2,
                    'releases_sent': 0,
                    'requests_sent': 0,
                    'session_name': '00:01:00:02:00:02',
                    'currently_attempting': 0,
                    'currently_idle': 0,
                    'currently_bound': 1,
                    'vlan_id': None}
               },
             'group': 
                {'9fdbf943-17fc-4deb-9cbd-b8a051ed04f9':
                   {'currently_attempting': 0,
                    'currently_idle': 0,
                    'currently_bound': 2,
                    'bound_renewed': 0,
                    'total_attempted': 0,
                    'total_bound': 0,
                    'total_failed': 0,
                    'discover_tx_count': 0,
                    'request_tx_count': 0,
                    'release_tx_count': 0,
                    'ack_rx_count': 0,
                    'nak_rx_count': 0,
                    'offer_rx_count': 0}
                }
            }
        )
        expected = {'2001:110::895f': '0001.0002.0001', '2001:110::9831': '0001.0002.0002'}
        #Act
        result=dev.get_dhcp_client_ip_mac_details(interface=1)
        #Assert
        self.assertEqual(expected, result)

    def test_add_dhcp_emulator_non_bvm_client(self):
        # Arrange
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.emulation_dhcp_group_config = Mock(return_value={'handle': '880ec248-9d18-4305-b120-9f316bd58c92'})
        expected = '880ec248-9d18-4305-b120-9f316bd58c92'
        #Act
        result = dev.add_dhcp_emulator_non_bvm_client(session_handle='handle')
        #Assert
        self.assertEqual(expected, result)

    def test_connect_and_boot_trex_negative(self):
        trex_ssh_connection = MockDeviceSSHWrapper(hostname='trex4', device_os='trex', port=0,
                                                   mock_data_dir='mock_data', state='start_test_off',
                                                   credentials={'trex': 'trex'})
        trex_ssh_connection.start()
        testbed = \
        """
        devices:
            trex4:
                os: trex
                credentials:
                    ssh:
                        username: trex
                        password: trex
                connections:
                    defaults:
                        class: genie.trafficgen.trex.Trex

                    hltapi:
                        device_ip: localhost
                        port: {}
                        username: trex
                        reset: true
                        break_locks: true
                        raise_errors: true
                        verbose: critical
                        timeout: 15
                        port_list: [0, 1]
                        ip_src_addr: 1.1.1.1
                        ip_dst_addr: 2.2.2.2
                        intf_ip_list: [None]
                        gw_ip_list: [None]
                        trex_path: /opt/trex
                        autostart: True
        """.format(trex_ssh_connection.ports[0])
        tb = loader.load(testbed)
        try:
            tb.devices.trex4.instantiate(via='hltapi')
            # Overloads disconnect key sequence because control keys do not work when passed through SSH Wrapper
            tb.devices.trex4.default.screen_exit_keys = 'sendline(__exit_screen_in_unittest__)'
            tb.devices.trex4.default._trex=Mock()
            tb.devices.trex4.connect()
        finally:
            tb.devices.trex4.disconnect()
        trex_ssh_connection.stop()

    def test_connect_and_boot_trex_positive(self):
        trex_ssh_connection = MockDeviceSSHWrapper(hostname='trex4', device_os='trex', port=0,
                                                   mock_data_dir='mock_data', state='start_test_on',
                                                   credentials={'trex': 'trex'})
        trex_ssh_connection.start()
        testbed = \
        """
        devices:
            trex4:
                os: trex
                credentials:
                    ssh:
                        username: trex
                        password: trex
                connections:
                    defaults:
                        class: genie.trafficgen.trex.Trex

                    hltapi:
                        device_ip: localhost
                        port: {}
                        username: trex
                        reset: true
                        break_locks: true
                        raise_errors: true
                        verbose: critical
                        timeout: 15
                        port_list: [0, 1]
                        ip_src_addr: 1.1.1.1
                        ip_dst_addr: 2.2.2.2
                        intf_ip_list: [None]
                        gw_ip_list: [None]
                        trex_path: /opt/trex
                        autostart: True
        """.format(trex_ssh_connection.ports[0])
        tb = loader.load(testbed)
        try:
            tb.devices.trex4.instantiate(via='hltapi')
            tb.devices.trex4.default._trex=Mock()
            tb.devices.trex4.connect()
        finally:
            tb.devices.trex4.disconnect()
            del tb
        trex_ssh_connection.stop()

    def test_configure_traffic_profile_by_custom(self):
        dev = self.dev
        dev.default._trex = Mock()
        dev._trex.traffic_config = Mock(return_value={"stream_id": 1})
        expected = True

        traffic_args = {
            'bidirectional': False,
            'frame_size': 70,
            'port_handle': 0,
            'mac_src': '00:00:01:00:00:01',
            'mac_src_mode': 'increment',
            'mac_src_count': 2500,
            'mac_dst': '00:00:02:00:00:00',
            'l3_protocol': 'ipv4',
            'ip_src_addr': '44.44.44.44',
            'ip_src_mode': 'fixed',
            'ip_dst_addr': '55.55.55.55',
            'ip_dst_mode': 'fixed',
            'rate_pps': 2000
        }
        dev.configure_traffic_profile_by_custom(**traffic_args)
        result = dev._traffic_profile_configured
        #Assert
        self.assertEqual(expected, result)
