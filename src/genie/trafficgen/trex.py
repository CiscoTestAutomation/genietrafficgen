
import time
import logging
import ipaddress
from prettytable import PrettyTable

# pyATS
from pyats.log.utils import banner
from pyats.connections import BaseConnection

# Genie
from genie.utils.timeout import Timeout
from genie.utils.summary import Summary
from genie.harness.utils import get_url
from genie.trafficgen.trafficgen import TrafficGen
from genie.harness.exceptions import GenieTgnError

# TRex
import trex_hltapi
from trex_hltapi.hltapi import TRexHLTAPI

# Logger
log = logging.getLogger(__name__)

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
                                    "for device '{d}'".\
                                            format(k=key, d=self.device.name))

    def configure_interface(self, arp_send_req=False, arp_req_retries=3, \
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
                    vlan=vlan
                    )
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to configure interfaces on TRex device") from e
                                            
    def isconnected(self):
        ''' Method to check connectivity to TRex device '''
        return self._trex is not None and self._trex.is_connected()

    def connect(self, configure_interface=True):
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
        if configure_interface:
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

    def stop_traffic(self, wait_time=10, unconfig_traffic=True, print_stats=False):
        '''Stop traffic on all ports on TRex'''

        log.info(banner("Stopping traffic for all ports on TRex"))
        # Stop traffic
        try:
            stop_traffic = self._trex.traffic_control(action = 'stop', port_handle = self.port_list[1])
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
