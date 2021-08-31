
import time
import logging
import ipaddress
from prettytable import PrettyTable

# pyATS
from pyats.log.utils import banner

# Genie
from genie.trafficgen.trafficgen import TrafficGen
from genie.harness.exceptions import GenieTgnError

# Logger
log = logging.getLogger(__name__)

# TRex
try:
    from trex_hltapi.hltapi import TRexHLTAPI
    from trex_hltapi import DhcpMessageType
except:
    log.warning('trex_hltapi must be installed to use the trex traffic gen')

class Trex(TrafficGen):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._is_connected = False
        self._traffic_profile_configured = False
        self._latest_stats = {}
        self._latest_stats_stream = {}
        self._traffic_statistics_table = PrettyTable()
        self._traffic_statistics_table_stream = PrettyTable()
        self._traffic_streams = []

        # Internal variables
        self.igmp_clients = {}

        # Get TRex device from testbed
        try:
            self._trex = TRexHLTAPI()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("TRex API returned error") from e

        log.info(self.connection_info)

        for key in ['username', 'reset', 'break_locks', 'raise_errors', \
            'verbose', 'timeout', 'device_ip', 'port_list', 'ip_src_addr', \
            'ip_dst_addr', 'intf_ip_list', 'gw_ip_list']:
            try:
                setattr(self, key, self.connection_info[key])
            except Exception:
                raise GenieTgnError("Argument '{k}' not found in testbed"
                                    "for device '{d}'"
                                    .format(k=key, d=self.device.name))

    def configure_interface(self, arp_send_req=False, arp_req_retries=3,
                            multicast=False, vlan=False):
        ''' Method to configure the interfaces on the TRex device.
            This needs to be configured before starting traffic. '''

        try:
            self._trex.interface_config(
                    port_handle=self.port_list,
                    arp_send_req=arp_send_req,
                    arp_req_retries=arp_req_retries,
                    intf_ip_addr=self.intf_ip_list,
                    gateway=self.gw_ip_list,
                    multicast=multicast,
                    vlan=vlan)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure interfaces on TRex device") from e

    def isconnected(self):
        ''' Method to check connectivity to TRex device '''
        return self._trex is not None and self._trex.is_connected()

    def connect(self, configure_interface_flag=True):
        '''Connect to TRex'''

        log.info(banner("Connecting to TRex"))

        # try connecting
        try:
            self._trex.connect(device = self.device_ip,
                               username = self.username,
                               reset = self.reset,
                               break_locks = self.break_locks,
                               raise_errors = self.raise_errors,
                               verbose = self.verbose,
                               timeout = self.timeout,
                               port_list = self.port_list)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to connect to TRex device") from e
        else:
            self._is_connected = self.isconnected()
            log.info("Connected to TRex successfully")

        # configure the interfaces on the TREX, the interfaces have to
        # configured before starting the traffic
        if configure_interface_flag:
            self.configure_interface()

    def disconnect(self):
        ''' Disconnect from TRex, this will call _trex.traffic_config
        with mode = 'remove' and will also remove traffic, reset source
        and destination ip addresses, promiscuous modes and so on, and
        disconnects from TRex '''

        self._trex.cleanup_session(port_handle = 'all')
        self._is_connected = self.isconnected()

    def configure_traffic_profile(self, bidirectional=False, frame_size=60, ignore_macs=True,
            l3_protocol='ipv4', ip_src_mode='increment', ip_src_count=254,
            ip_dst_mode='increment', ip_dst_count=254, l4_protocol='udp',
            udp_dst_port=1209, udp_src_port=1025, rate_pps=1000, count=3):
        ''' Configure the traffic profile, the profile has to be configured
            before calling the start_traffic method.
        '''

        # This is just to get individual stream id for each dst IP/port pair
        # otherwise it just returns one stream-id
        ip_src_string = self.ip_src_addr
        ip_dst_string = self.ip_dst_addr
        for _ in range(count):
            try:
                config_status = self._trex.traffic_config(
                mode = 'create',
                bidirectional = bidirectional,
                port_handle = self.port_list[1],
                port_handle2 = self.port_list[0],
                frame_size = frame_size,
                ignore_macs = ignore_macs,
                l3_protocol = l3_protocol,
                ip_src_addr = ip_src_string,
                ip_src_mode = ip_src_mode,
                ip_src_count = ip_src_count,
                ip_dst_addr = ip_dst_string,
                ip_dst_mode = ip_dst_mode,
                ip_dst_count = ip_dst_count,

                l4_protocol = l4_protocol,
                udp_dst_port = udp_dst_port,
                udp_src_port = udp_src_port,

                rate_pps = rate_pps
            )
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Failed to configure traffice profile on TRex")
            else:
                self._traffic_streams.append(config_status['stream_id'])
                stream_list = str(self._traffic_streams)[1:-1]
                log.info("Traffic config streams: " + stream_list)

            log.info("Src IP: " + ip_src_string)
            log.info("Dst IP: " + ip_dst_string)
            ip_src_string = str(ipaddress.IPv4Address(ip_src_string) + 1)
            ip_dst_string = str(ipaddress.IPv4Address(ip_dst_string) + 1)

        self._traffic_profile_configured = True

    def configure_dhcpv4_request(self, mac_src, l3addr, xid, length_mode='auto',
                            mac_dst='ff:ff:ff:ff:ff:ff', l3_protocol='ipv4',
                            ip_src_addr='0.0.0.0', ip_dst_addr='255.255.255.255',
                            transmit_mode='single_burst', num=1, pps=100):
        ''' Method to configure a DHCPv4 REQUEST stream '''

        try:
            config_status = self._trex.traffic_config (
                mode='create',
                port_handle=self.port_list[0],
                length_mode=length_mode,
                mac_src=mac_src,
                mac_dst=mac_dst,
                l3_protocol=l3_protocol,
                ip_src_addr=ip_src_addr,
                ip_dst_addr=ip_dst_addr,

                l4_protocol='dhcp',
                dhcp_transaction_id=xid,
                dhcp_client_hw_addr=mac_src,
                dhcp_client_ip_addr=l3addr,
                dhcp_option=['dhcp_message_type'],
                dhcp_option_data=[DhcpMessageType.REQUEST],
                transmit_mode=transmit_mode,
                pkts_per_burst=num,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure dhcpv4 request stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def configure_dhcpv4_reply(self, mac_src, l3addr, xid, lease_time, length_mode='auto',
                            mac_dst='ff:ff:ff:ff:ff:ff', l3_protocol='ipv4',
                            ip_src_addr='192.168.11.1', ip_dst_addr='255.255.255.255',
                            transmit_mode='single_burst', num=1, pps=100):
        ''' Method to configure a DHCPv4 REPLY stream '''

        try:
            config_status = self._trex.traffic_config(
                mode='create',
                port_handle=self.port_list[0],
                length_mode=length_mode,
                mac_src=mac_src,
                mac_dst=mac_dst,
                l3_protocol=l3_protocol,
                ip_src_addr=ip_src_addr,
                ip_dst_addr=ip_dst_addr,

                l4_protocol='dhcp',
                dhcp_transaction_id=xid,
                dhcp_operation_code='reply',
                dhcp_client_hw_addr=mac_src,
                dhcp_your_ip_addr=l3addr,
                dhcp_option=['dhcp_message_type', 'dhcp_ip_addr_lease_time'],
                dhcp_option_data=[DhcpMessageType.ACK, lease_time],
                transmit_mode=transmit_mode,
                pkts_per_burst=num,
                rate_pps=pps
            )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure dhcpv4 reply stream on TRex")
        else:
            self._traffic_streams.append(config_status['stream_id'])
            stream_list = str(self._traffic_streams)[1:-1]
            log.info("Traffic config streams: " + stream_list)

        self._traffic_profile_configured = True

    def get_traffic_stream_names(self):
        '''Returns a list of all traffic stream names present in current
        configuration'''

        return self._traffic_streams

    def start_traffic(self, wait_time=10):
        '''Start traffic on TRex'''

        # Configure traffic profile first
        if not self._traffic_profile_configured:
            self.configure_traffic_profile()

        log.info(banner("Starting traffic on TRex"))
        # Start traffic
        try:
            start_traffic = self._trex.traffic_control(action = 'run', port_handle = self.port_list)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)

    def start_traffic_streams(self, wait_time=5, streams = None):
        '''Start traffic on TRex'''

        if not streams:
            streams = self._traffic_streams
        # Configure traffic profile first
        if not self._traffic_profile_configured:
            self.configure_traffic_profile()

        log.info(banner("Starting port trasmit first on TRex"))
        ## Start traffic
        try:
            start_traffic = self._trex.traffic_control(action = 'run', port_handle = self.port_list[1])
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds after configuring ports".format(d = wait_time))
        time.sleep(wait_time)
        # Start traffic per stream
        try:
            start_traffic = self._trex.traffic_control(action = 'run', handle = streams)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic per stream on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds after starting traffic".format(d = wait_time))
        time.sleep(wait_time)

    def unconfigure_traffic(self):
        '''Unconfigure traffic. This will remove the profile configured.
           There is an option to unconfigure per port as well.
        '''

        log.info(banner("Unconfiguring TRex traffic profile"))
        try:
            self._trex.traffic_config(mode = 'remove', port_handle = self.port_list, stream_id = 'all')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to unconfigure traffic profile on TRex")
        log.info(banner("Unconfigured TRex traffic profile"))

        self._traffic_profile_configured = False

    def stop_traffic(self, wait_time=10, unconfig_traffic=True, print_stats=False):
        '''Stop traffic on all ports on TRex'''

        log.info(banner("Stopping traffic for all ports on TRex"))
        # Stop traffic
        try:
            stop_traffic = self._trex.traffic_control(action = 'stop', port_handle = self.port_list)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)

        if print_stats:
            self.print_statistics(mode='aggregate')

        # Get the _traffic_statistics_table before unconfiguring
        self._traffic_statistics_table = self.create_traffic_statistics_table()
        log.info(self._traffic_statistics_table)
        # if needed to unconfigure traffic after stopping
        if unconfig_traffic:
            self.unconfigure_traffic()

    def stop_traffic_streams(self, wait_time=5, unconfig_traffic=False, streams = None, print_stats = False):
        '''Stop traffic on given streams on TRex'''

        log.info(banner("Stopping traffic for given streams on TRex"))
        if streams is None:
            streams = self._traffic_streams
        # Stop traffic
        try:
            stop_traffic = self._trex.traffic_control(action = 'stop', handle = streams)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)

        if print_stats:
            self.print_statistics(mode='streams')

        # Get the _traffic_statistics_table before unconfiguring
        self._traffic_statistics_table_stream = self.create_traffic_statistics_table_stream(traffic_streams = streams)

        log.info(self._traffic_statistics_table)
        # if needed to unconfigure traffic after stopping
        if unconfig_traffic:
            self.unconfigure_traffic()

    def print_statistics(self, mode = 'aggregate'):
        '''Print traffic related statistics'''
        res = self._trex.traffic_stats(mode = mode, port_handle = self.port_list)
        log.info(res)

    def clear_statistics(self, port_handle_clear=None, wait_time=5, clear_port_stats=True,
                         clear_protocol_stats=True):
        '''Clear all traffic, port, protocol statistics on TRex'''

        log.info(banner("Clearing traffic statistics"))
        # Clear trafficstats, TRex api does not support per port/protocol clear
        if not port_handle_clear:
            log.info("Clearing statistics for all ports since port handle is empty")
            port_handle_clear = self.port_list

        if not clear_port_stats:
            return

        try:
            clear_traffic_stats = self._trex.traffic_control(action="clear_stats", port_handle=port_handle_clear)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to clear traffic stats on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Successfully cleared traffic statistics on device\
                     '{dev}'".format(dev=self.device.name))

        # Wait after clearing statistics
        log.info("Waiting for '{}' seconds after clearing statistics".\
                    format(wait_time))
        time.sleep(wait_time)

    def create_traffic_statistics_table(self, set_golden=False, clear_stats=False, clear_stats_time=30, view_create_interval=30, view_create_iteration=5):
        '''Returns traffic profile of configured streams on TRex'''

        # Initialize the table
        traffic_table = PrettyTable()
        traffic_table.field_names = ['Port', 'Tx/Rx', 'Packet Bit Rate',
                                     'Packet Byte Count',
                                     'Packet Count', 'Packet Rate',
                                     'Total_pkt_bytes', 'Total Packet Rate',
                                     'Total Packets']

        stat = self._trex.traffic_stats(mode = 'aggregate',
                                        port_handle = self.port_list)
        self._latest_stats = stat
        for port in stat:
            data = [port, 'Tx']
            for key in stat[port]['aggregate']['tx']:
                data.append(stat[port]['aggregate']['tx'][key])
            traffic_table.add_row(data)
            # remove the values from Tx from 1:end, since these have been added
            # to the table now
            del data[1:]
            data.append('Rx')
            for key in stat[port]['aggregate']['rx']:
                data.append(stat[port]['aggregate']['rx'][key])
            traffic_table.add_row(data)

        return traffic_table

    def create_traffic_statistics_table_stream(self, set_golden=False,
            clear_stats=False, clear_stats_time=30, view_create_interval=30,
            view_create_iteration=5, traffic_streams=None):
        '''Returns traffic profile of configured streams on TRex'''

        if not traffic_streams:
            log.info("Need to specify the stream_id to create the stats table")
            traffic_streams = self._traffic_streams

        for stream in traffic_streams:
            if stream not in self._traffic_streams:
                log.info("Stream: '{s}' not configured".format(s=stream))

        # Initialize the table
        traffic_table = PrettyTable()
        traffic_table.field_names = ['Port', 'Stream', 'Tx/Rx', 'Total pkts', 'Total_pkt_bytes', 'Total_pkt_bit_rate', 'Total_pkt_rate', 'line rate percent']

        # TODO: no hltapi to check if stat is empty?
        # stat is 'trex_hltapi.utils.wrappers.HltApiResult'
        stat = self._trex.traffic_stats(mode = 'streams',
                                        port_handle = self.port_list)

        self._latest_stats_stream  = stat
        for port in stat:
            num_streams = len(stat[port]['stream'])
            for stream_id in stat[port]['stream'].keys():
                data = [port, str(stream_id), 'tx']
                for key in stat[port]['stream'][str(stream_id)]['tx'].keys():
                    data.append(stat[port]['stream'][str(stream_id)]['tx'][key])
                traffic_table.add_row(data)
                # remove the values from Tx from 2:end, since these have been added
                # to the table now
                del data[2:]
                data.append('rx')
                for key in stat[port]['stream'][str(stream_id)]['rx'].keys():
                    data.append(stat[port]['stream'][str(stream_id)]['rx'][key])
                traffic_table.add_row(data)

        return traffic_table

    # Multicast APIs
    def create_multicast_group(self, groupip, inc_steps='0.0.0.0',
                               ip_prefix_len=32, group_nums=1):
        '''Create multicast group pool
           Args:
             groupip ('str'): group ipv4/ipv6 address
             inc_steps ('str'): Used to increment group address
             ip_prefix_len ('int'): Defaults to 32 for IPv4 and 128 for IPv6.
             group_nums ('int'): number of groups
           Returns:
             multicast group pool handler
        '''
        grp_hdl = self._trex.emulation_multicast_group_config(mode='create',
                                                             ip_addr_start=groupip,
                                                             ip_prefix_len=ip_prefix_len,
                                                             ip_addr_step=inc_steps,
                                                             num_groups=group_nums)
        return grp_hdl

    def delete_multicast_group(self, group_handler):
        '''delete multicast group pool
           Args:
             group_handler ('obj'): multicast group pool handler
           Returns:
             True
        '''
        self._trex.emulation_multicast_group_config(mode='delete',
                                                    handle=group_handler.handle)
        return True

    def create_multicast_source(self, sourceip, inc_steps='0.0.0.0',
                                ip_prefix_len=32, source_nums=1):
        '''Create multicast source pool
           Args:
             sourceip ('str'): source ipv4/ipv6 address
             inc_steps ('str'): Used to increment source address
             ip_prefix_len ('int'): Defaults to 32 for IPv4 and 128 for IPv6.
             source_nums ('int'): number of sources
           Returns:
             multicast source pool handler
           Raises:
             KeyError
        '''
        multicast_handle = self._trex.emulation_multicast_source_config(mode='create',
                                                                        ip_addr_start=sourceip,
                                                                        ip_addr_step=inc_steps,
                                                                        ip_prefix_len=ip_prefix_len,
                                                                        num_sources=source_nums)
        if not multicast_handle:
            log.warn('multicast source creation failed')
            raise KeyError
        return multicast_handle

    def delete_multicast_source(self, source_handler):
        '''delete multicast source pool
           Args:
             source_handler ('obj'): multicast source pool handler
           Returns:
             True
        '''
        self._trex.emulation_multicast_source_config(mode='delete',
                                                     handle=source_handler.handle)
        return True
    
    # IGMP APIs
    def create_igmp_client(self, interface, clientip, version, vlanid=0):
        '''Create IGMP Client
           Args:
             interface ('str'): interface name
             clientip ('str'): ip address
             version ('int'): 2 or 3
             vlanid ('int'): vlan id
           Returns:
             igmp client handler
        '''
        if version == 2:
            version = 'v2'
        else:
            version = 'v3'

        handle = self._get_igmpclient_hkey(interface, vlanid, clientip, version)
        self._update_igmpclient_field(handle.handles[0], 'vlan', vlanid)
        self._update_igmpclient_field(handle.handles[0], 'version', version)

        return handle

    def delete_igmp_client(self, client_handler):
        '''Delete IGMP Client
           Args:
             client_handler ('obj'): IGMP Client handler
           Returns:
             True/False
        '''
        #need to be changed
        intf = self._get_igmpclient_field(client_handler.handles[0], 'interface')
        self._trex.emulation_igmp_config(mode = 'delete', 
                                         handle = client_handler.handles[0],
                                         intf_ip_addr = intf)
        return self._del_igmpclient_hkey(client_handler.handles[0])

    def igmp_client_add_group(self, client_handler,
                              group_handler,
                              source_handler=None,
                              filter_mode='N/A'):
        '''IGMP Client add group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             group_handler ('obj'):
                Multicast group pool handler created by create_multicast_group
             source_handler ('obj'):
                Multicast source handler created by create_multicast_source
                by default is None, means (*, g)
             filter_mode ('str'): include | exclude | N/A (by default)

             for v3 (*,g) which is (0.0.0.0, g)-exclude, the source_handler
             should be None, filter_mode should be exclude
           Returns:
             group membership handler
        '''
        if filter_mode == 'N/A':
            filter_mode = None

        if source_handler:
            source_handler = source_handler.handle

        grp_hdl = self._trex.emulation_igmp_group_config(mode='create',
                                                         session_handle=client_handler.handles[0],
                                                         source_pool_handle=source_handler,
                                                         group_pool_handle=group_handler.handle,
                                                         g_filter_mode=filter_mode)
        
        self._add_igmpgroup(source_handler, client_handler.handles[0], group_handler.handle, grp_hdl.handle)
        self._filter_update(client_handler.handles[0], grp_hdl.handle, filter_mode)

        return grp_hdl

    def igmp_client_modify_group_filter_mode(self, client_handler,
                                             handler, filter_mode=None, action=None):
        '''IGMP Client modify group member filter mode, Only IGMP v3
           client is supported
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
             filter_mode: include | exclude
           Returns:
             Updated Group membership handler
        '''
        self._trex.emulation_igmp_group_config(mode='modify',
                                               handle=handler.handle,
                                               session_handle=client_handler.handles[0],
                                               g_filter_mode='change_to_'+filter_mode)

        self._filter_update(client_handler.handles[0], handler.handle, filter_mode)
        return handler

    def igmp_client_del_group(self, client_handler, handler, action=None):
        '''IGMP Client delete group membership
           Args:
             client_handler ('obj'): IGMP Client handler
             handler ('obj'):
                Group membership handler created by igmp_client_add_group
           Returns:
             True
           Raises:
             KeyError
        '''
        self._trex.emulation_igmp_group_config(mode='delete',
                                               handle=handler.handle,
                                               session_handle=client_handler.handles[0],
                                               g_action=action)
        grps = self._get_igmpclient_field(client_handler.handles[0], 'grps')
        if handler.handle not in grps:
            log.error('Group does not exist')
            raise KeyError
        
        grps.remove(handler.handle)
        self._update_igmpclient_field(client_handler.handles[0], 'grps', grps)
        return True

    def igmp_client_control(self, interface, client_handler, mode):
        '''IGMP Client protocol control
           Args:
             interface ('str'): interface name
             client_handler: IGMP Client handler
             mode ('mode'):
                start: start the client with sending igmp join message
                stop: stop the client with sending igmp leave message
                restart: restart the client
           Returns:
             True
        '''
        version = self._get_igmpclient_field(client_handler.handles[0], 'version')
        if mode == 'start':
            if version == 'v2':
                self._trex.emulation_igmp_control(mode = 'join',
                                                  port_handle=interface)
            else:
                self._trex.emulation_igmp_control(mode = 'start',
                                                  port_handle=interface)      
        else:
            grps = self._get_igmpclient_field(client_handler.handles[0], 'grps')

            if version == 'v2':
                for grp in grps:
                    filt = self.igmp_clients[client_handler.handles[0]]['filters'][grps[grp]['*']]
                    self._trex.emulation_igmp_group_config(mode='modify',
                                                            session_handle=client_handler.handles[0],
                                                            handle=grps[grp]['*'],
                                                            g_action='leave',
                                                            g_filter_mode=None)
                
                self._trex.emulation_igmp_control(port_handle=interface,
                                                  mode='start')
            else:
                for grp in grps:
                    for src in grps[grp]:
                        self._trex.emulation_igmp_group_config(mode='delete',
                                                               handle=grps[grp][src],
                                                               session_handle=client_handler.handles[0])
                        #get filter
                        filt = self.igmp_clients[client_handler.handles[0]]['filters'][grps[grp][src]]
                        if filt == 'include':
                            g_filter = 'block_old_source'
                            grp_hdl = self._trex.emulation_igmp_group_config(mode='create',
                                                                             session_handle=client_handler.handles[0],
                                                                             group_pool_handle=grp,
                                                                             source_pool_handle='{}/0.0.0.0/1'.format(src),
                                                                             g_filter_mode=g_filter)
                            self._add_igmpgroup(src, client_handler.handles[0], grp, grp_hdl.handle)
                            self._filter_update(client_handler.handles[0], grp_hdl.handle, 'block_old_source')
                        else:
                            g_filter = 'change_to_include'
                            grp_hdl = self._trex.emulation_igmp_group_config(mode='create',
                                                                             session_handle=client_handler.handles[0],
                                                                             group_pool_handle=grp,
                                                                             g_filter_mode=g_filter)
                            self._add_igmpgroup(src, client_handler.handles[0], grp, grp_hdl.handle)
                            self._filter_update(client_handler.handles[0], grps[grp][src], 'change_to_include')

                self._trex.emulation_igmp_control(port_handle=interface,
                                                  mode='start')
        return True


    # =============================================================
    # IGMP Client management methods
    # Allocate a clientkey to track all the clients
    # This set of methods used to manage the igmp clients of pagent
    # ==============================================================

    def _get_igmpclient_hkey(self, interface, vlanid, clientip, version):
        '''Get host key of igmp client, create a new key for new client
           Args:
             vlanid ('int'): vlan id
             clientip ('str'): client ip address
           Returns:
             handle of igmp client
        '''
        client_hdl = self._trex.emulation_igmp_config(mode='create',
                                                      port_handle=interface,
                                                      intf_ip_addr=clientip,
                                                      version=version,
                                                      vlan_id=vlanid)

        if client_hdl.handles[0] not in self.igmp_clients:
            self.igmp_clients[client_hdl.handles[0]] = {
                'version': version,
                'grps': {},
                'filters': {},
                'interface': interface,
            }

        return client_hdl

    def _del_igmpclient_hkey(self, handle):
        '''Delete a igmp client host
           Args:
             hkey ('str'): igmp client host key
           Returns:
             True/False
           Raises:
             None
        '''
        if handle in self.igmp_clients:
            del self.igmp_clients[handle]
            return True

        return False

    def _update_igmpclient_field(self, handle, key, value):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
             value ('any'): field value
           Returns:
             None
           Raises:
             None
        '''
        self.igmp_clients[handle][key] = value
        log.info(
            'Client {handle} update: {key}'.format(
                handle=handle, key=key
            )
        )

    def _get_igmpclient_field(self, client_hdl, key):
        '''Update igmpclient field by host key
           Args:
             hkey ('str'): igmp client host key
             key ('any'): field key
           Returns:
             field value
           Raise:
             KeyError
        '''
        val = self.igmp_clients[client_hdl][key]
        if not val:
            log.warn('Key not in dictionary')
            raise KeyError
        return val
    
    def _filter_update(self, client, grp_hdl, filter):
        '''Update filter by group member handle
           Args:
             client_handle ('str')
             group member handle ('str')
             filter('str')
           Return:
             True
           Raise:
             KeyError
        '''
        if grp_hdl not in self.igmp_clients:
            raise KeyError
        self.igmp_clients[client]['filters'][grp_hdl] = filter
        return True
    
    def _add_igmpgroup(self, source_handler, client_handler, group_handler, grp_hdl):
        '''Add igmpclient to group
           Args:
             source_handle ('str'): source ghandle key
             client_handler (dictionary): client handle
             group_handler (dictionary): group handle
             grp_hdl (dictionary): group member handle
           Returns:
             True
           Raise:
             KeyError
        '''
        if client_handler not in self.igmp_clients:
            raise KeyError
        if group_handler not in self.igmp_clients[client_handler]['grps']:
            self.igmp_clients[client_handler]['grps'][group_handler]={}
        if not source_handler:
            self.igmp_clients[client_handler]['grps'][group_handler]['*']=grp_hdl
        else:
            self.igmp_clients[client_handler]['grps'][group_handler][source_handler]=grp_hdl

        '''filter initialization'''
        self.igmp_clients[client_handler]['filters'][grp_hdl] = None
        return True