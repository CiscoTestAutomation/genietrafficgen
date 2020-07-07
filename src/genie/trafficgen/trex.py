
import time
import logging

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

        # Get TRex device from testbed
        try:
            self._trex = TRexHLTAPI()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("TRex API returned error") from e

        log.info(self.connection_info)

        for key in ['username', 'reset', 'break_locks', 'raise_errors', \
            'verbose', 'timeout', 'device_ip', 'port_list', 'ip_src_addr', \
            'ip_dst_addr', 'gw_src_ip', 'gw_dst_ip']:
            try:
                setattr(self, key, self.connection_info[key])
            except Exception:
                raise GenieTgnError("Argument '{k}' not found in testbed"
                                    "for device '{d}'".\
                                            format(k=key, d=self.device.name))

    def configure_interface(self, arp_send_req=False, arp_req_retries=3, \
        multicast=[True, False], vlan=False):
        ''' Method to configure the interfaces on the TRex device. 
            This needs to be configured before starting traffic. '''

        try:
            self._trex.interface_config(
                    port_handle=self.port_list,
                    arp_send_req=arp_send_req,
                    arp_req_retries=arp_req_retries,
                    intf_ip_addr=[self.ip_src_addr,self.ip_dst_addr],
                    gateway=[self.gw_src_ip, self.gw_dst_ip],
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

    def configure_traffic_profile(self, bidirectional=True, frame_size=60, ignore_macs=True,
            l3_protocol='ipv4', ip_src_mode='increment', ip_src_count=254,
            ip_dst_mode='increment', ip_dst_count=254, l4_protocol='udp', 
            udp_dst_port=12, udp_src_port=1025, rate_pps=1000):
        ''' Configure the traffic profile, the profile has to be configured
            before calling the start_traffic method.
        '''
        try:
            res = self._trex.traffic_config(
            mode = 'create',
            bidirectional = bidirectional,
            port_handle = self.port_list[0],
            port_handle2 = self.port_list[1],
            frame_size = frame_size,
            
            ignore_macs = ignore_macs,

            l3_protocol = l3_protocol,
            ip_src_addr = self.ip_src_addr,
            ip_src_mode = ip_src_mode,
            ip_src_count = ip_src_count,
            ip_dst_addr = self.ip_dst_addr,
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

    def start_traffic(self, wait_time=10):
        '''Start traffic on TRex'''

        # Configure traffic profile first
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

    def stop_traffic(self, wait_time=10, unconfig_traffic=True):
        '''Stop traffic on TRex'''

        log.info(banner("Stopping traffic on TRex"))
        # Stop traffic
        try:
            stop_traffic = self._trex.traffic_control(action = 'stop', port_handle = self.port_list)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        log.info("Sleeping for {d} seconds".format(d = wait_time))
        time.sleep(wait_time)
       
        # print stats
        res = self._trex.traffic_stats(mode = 'aggregate', port_handle = self.port_list)
        log.info(res)
        # if needed to unconfigure traffic after stopping
        if unconfig_traffic:
            self.unconfigure_traffic()


