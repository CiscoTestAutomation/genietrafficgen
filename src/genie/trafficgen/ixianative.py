'''
Connection Implementation class for Ixia traffic generator using
ixnetwork Python package to interact with Ixia device:
https://pypi.org/project/ixnetwork/

Requirements:
    * IxOS/IxVM 7.40 or higher
    * IxNetork EA version 7.40 or higher
'''

# Python
import os
import logging
import time
import re
import prettytable

# pyATS
from ats.log.utils import banner
from ats.connections import BaseConnection

# Genie
from genie.trafficgen.trafficgen import TrafficGen
from genie.utils.summary import Summary
from genie.harness.utils import get_url
from genie.harness.exceptions import GenieTgnError

# IxNetwork Native
try:
    from IxNetwork import IxNet
except ImportError as e:
    raise ImportError("IxNetwork package is not installed in virtual env - "
                      "https://pypi.org/project/IxNetwork/") from e

# Logger
log = logging.getLogger(__name__)

# ixNet pass
_PASS = '::ixNet::OK'


class IxiaNative(TrafficGen):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        # Init class variables
        self.ixNet = IxNet()
        self._is_connected = False
        self.virtual_ports = []
        self._genie_view = None
        self._genie_page = None
        self._golden_profile = prettytable.PrettyTable()

        # Get Ixia device arguments from testbed YAML file
        for key in ['ixnetwork_api_server_ip', 'ixnetwork_tcl_port',
                    'ixia_port_list', 'ixnetwork_version', 'ixia_chassis_ip',
                    'ixia_license_server_ip']:
            # Verify Ixia ports provided are a list
            if key is 'ixia_port_list':
                if not isinstance(self.connection_info[key], list):
                    log.error("Attribute '{}' is not a list as expected".\
                              format(key))
            try:
                setattr(self, key, self.connection_info[key])
            except Exception:
                raise GenieTgnError("Argument '{k}' is not found in testbed "
                                    "YAML for device '{d}'".\
                                    format(k=key, d=self.device.name))

        # Genie Traffic Documentation
        log.info('For more information, see Genie traffic documention: '
                 '{url}/harness/user/ixia.html'.format(url=get_url()))


    def get_golden_profile(self):
        ''' Returns golden profile'''
        return self._golden_profile


    def connect(self):
        '''Connect to Ixia'''

        # If already connected do nothing
        if self._is_connected:
            return

        log.info(banner("Connecting to IXIA"))

        # Ixia Chassis Details
        header = "Ixia Chassis Details"
        summary = Summary(title=header, width=45)
        summary.add_message(msg='IxNetwork API Server: {}'.\
                            format(self.ixnetwork_api_server_ip))
        summary.add_sep_line()
        summary.add_message(msg='IxNetwork API Server Platform: Windows')
        summary.add_sep_line()
        summary.add_message(msg='IxNetwork Version: {}'.\
                         format(self.ixnetwork_version))
        summary.add_sep_line()
        summary.add_message(msg='Ixia Chassis: {}'.\
                         format(self.ixia_chassis_ip))
        summary.add_sep_line()
        summary.add_message(msg='Ixia License Server: {}'.\
                         format(self.ixia_license_server_ip))
        summary.add_sep_line()
        summary.add_message(msg='Ixnetwork TCL Port: {}'.\
                         format(self.ixnetwork_tcl_port))
        summary.add_sep_line()
        summary.print()

        # Execute connect on IxNetwork
        try:
            connect = self.ixNet.connect(self.ixnetwork_api_server_ip,
                                        '-port', self.ixnetwork_tcl_port,
                                        '-version', self.ixnetwork_version,
                                        '-setAttribute', 'strict')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to connect to device '{d}' on port "
                                "'{p}'".format(d=self.device.name,
                                            p=self.ixnetwork_tcl_port)) from e
        # Verify return
        try:
            assert connect == _PASS
        except AssertionError as e:
            log.error(connect)
            raise GenieTgnError("Failed to connect to device '{d}' on port "
                                "'{p}'".format(d=self.device.name,
                                            p=self.ixnetwork_tcl_port)) from e
        else:
            self._is_connected = True
            log.info("Connected to IxNetwork API server on TCL port '{p}'".\
                     format(d=self.device.name, p=self.ixnetwork_tcl_port))


    def _get_current_traffic_state(self):
        '''Returns current traffic state'''

        try:
            state = self.ixNet.getAttribute('/traffic', '-state')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get current traffic state") from e
        else:
            return state


    def load_configuration(self, configuration, wait_time=60):
        '''Load static configuration file onto Ixia'''

        log.info(banner("Loading configuration"))

        # Ixia Configuration Details
        header = "Ixia Configuration Information"
        summary = Summary(title=header, width=105)
        summary.add_message(msg='Ixia Ports: {}'.format(self.ixia_port_list))
        summary.add_sep_line()
        summary.add_message(msg='File: {}'.format(configuration))
        summary.add_sep_line()
        summary.print()

        # Execute load config on IxNetwork
        try:
            load_config = self.ixNet.execute('loadConfig', 
                                             self.ixNet.readFrom(configuration))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to load configuration file '{f}' onto "
                                "device '{d}'".format(d=self.device.name,
                                                f=configuration)) from e
        # Verify return
        try:
            assert load_config == _PASS
        except AssertionError as e:
            log.error(load_config)
            raise GenieTgnError("Unable to load configuration file '{f}' onto "
                                "device '{d}'".format(d=self.device.name,
                                                f=configuration)) from e
        else:
            log.info("Loaded configuration file '{f}' onto device '{d}'".\
                    format(f=configuration, d=self.device.name))

        # Wait after loading configuration file
        log.info("Waiting for '{}' seconds after loading configuration...".\
                 format(wait_time))
        time.sleep(wait_time)

        # Verify traffic is in 'unapplied' state
        log.info("Verify traffic is in 'unapplied' state after loading configuration")
        try:
            assert self._get_current_traffic_state() == 'unapplied'
        except AssertionError as e:
            raise GenieTgnError("Traffic is not in 'unapplied' state after "
                                "loading configuration onto device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Traffic in 'unapplied' state after loading configuration "
                     "onto device '{}'".format(self.device.name))

        # Assign Ixia ports for the configuration
        log.info(banner("Assigning Ixia ports"))

        # Get list of physical ports
        self.physical_ports = []
        for item in self.ixia_port_list:
            ixnet_port = []
            lc, port = item.split('/')
            for tmpvar in self.ixia_chassis_ip, lc, port:
                ixnet_port.append(tmpvar)
            self.physical_ports.append(ixnet_port)

        try:
            # Add the chassis
            self.chassis = self.ixNet.add(self.ixNet.getRoot() + \
                                          'availableHardware',\
                                          'chassis', '-hostname',\
                                          self.ixia_chassis_ip)
            self.ixNet.commit()
            self.chassis = self.ixNet.remapIds(self.chassis)

            # Create virtual ports for extracted physical ports
            self.virtual_ports = self.ixNet.getList(self.ixNet.getRoot(), 'vport')

            # Assign ports
            self.ixNet.execute('assignPorts', self.physical_ports, [],
                               self.virtual_ports, True)

            # Verify ports are up and connected
            for vport in self.virtual_ports:
                assert self.ixNet.getAttribute(vport, '-state') == 'up'
                assert self.ixNet.getAttribute(vport, '-isConnected') == 'true'
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error assigning Ixia ports") from e
        else:
            log.info("Assigned the following Ixia ports for configuration:")
            for port in self.ixia_port_list:
                log.info("-> Ixia Port: '{}'".format(port))


    def start_all_protocols(self, wait_time=60):
        '''Start all protocols on Ixia'''

        log.info(banner("Starting routing engine"))

        # Start protocols on IxNetwork
        try:
            start_protocols = self.ixNet.execute('startAllProtocols')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start all protocols on device '{}'".\
                                format(self.device.name)) from e
        # Verify return
        try:
            assert start_protocols == _PASS
        except AssertionError as e:
            log.error(start_protocols)
            raise GenieTgnError("Unable to start all protocols on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Started protocols on device '{}".format(self.device.name))

        # Wait after starting protocols
        log.info("Waiting for '{}' seconds after starting all protocols...".\
                    format(wait_time))
        time.sleep(wait_time)


    def stop_all_protocols(self, wait_time=60):
        '''Stop all protocols on Ixia'''

        log.info(banner("Stopping routing engine"))

        # Stop protocols on IxNetwork
        try:
            stop_protocols = self.ixNet.execute('stopAllProtocols')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop all protocols on device '{}".\
                                format(self.device.name)) from e
        # Verify return
        try:
            assert stop_protocols == _PASS
        except AssertionError as e:
            log.error(stop_protocols)
            raise GenieTgnError("Unable to stop all protocols on device '{}".\
                                format(self.device.name)) from e
        else:
            log.info("Stopped protocols on device '{}".format(self.device.name))

        # Wait after stopping protocols
        log.info("Waiting for  '{}' seconds after stopping all protocols...".\
                    format(wait_time))
        time.sleep(wait_time)


    def apply_traffic(self, wait_time=60):
        '''Apply L2/L3 traffic on Ixia'''

        log.info(banner("Applying L2/L3 traffic"))

        # Apply traffic on IxNetwork
        try:
            apply_traffic = self.ixNet.execute('apply', '/traffic')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to apply L2/L3 traffic on device '{}'".\
                                format(self.device.name)) from e
        # Verify return
        try:
            assert apply_traffic == _PASS
        except AssertionError as e:
            log.error(apply_traffic)
            raise GenieTgnError("Unable to apply L2/L3 traffic on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Applied L2/L3 traffic on device '{}'".format(self.device.name))

        # Wait after applying L2/L3 traffic
        log.info("Waiting for '{}' seconds after applying L2/L3 traffic...".\
                    format(wait_time))
        time.sleep(wait_time)

        # Verify traffic is in 'stopped' state
        log.info("Verify traffic is in 'stopped' state...")
        try:
            assert self._get_current_traffic_state() == 'stopped'
        except Exception as e:
            raise GenieTgnError("Traffic is not in 'stopped' state after "
                                "applying L2/L3 traffic on device '{}'".\
                                format(self.device.name))
        else:
            log.info("Traffic is in 'stopped' state after applying traffic as "
                     "expected")


    def send_arp(self, wait_time=10):
        '''Send ARP to all interfaces from Ixia'''

        log.info(banner("Sending ARP to all interfaces from Ixia"))

        # Send ARP from Ixia
        try:
            send_arp = self.ixNet.execute('sendArpAll')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to send ARP to all interfaces on device"
                                " '{}'".format(self.device.name)) from e
        # Verify return
        try:
            assert send_arp == _PASS
        except AssertionError as e:
            log.error(send_arp)
            raise GenieTgnError("Unable to send ARP to all interfaces on device"
                                " '{}'".format(self.device.name)) from e
        else:
            log.info("Sent ARP to all interfaces on device '{}'".\
                    format(self.device.name))

        # Wait after sending ARP
        log.info("Waiting for '{}' seconds after sending ARP to all interfaces...".\
                    format(wait_time))
        time.sleep(wait_time)


    def send_ns(self, wait_time=10):
        '''Send NS to all interfaces from Ixia'''

        log.info(banner("Sending NS to all interfaces from Ixia"))

        # Sent NS from Ixia
        try:
            send_ns = self.ixNet.execute('sendNsAll')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error sending NS to all interfaces on device "
                                "'{}'".format(self.device.name)) from e
        try:
            assert send_ns == _PASS
        except AssertionError as e:
            log.error(send_ns)
            raise GenieTgnError("Error sending NS to all interfaces on device "
                                "'{}'".format(self.device.name)) from e
        else:
            log.info("Sent NS to all interfaces on device '{}'".\
                        format(self.device.name))

        # Wait after sending NS
        log.info("Waiting for '{}' seconds after sending NS...".\
                    format(wait_time))
        time.sleep(wait_time)


    def start_traffic(self, wait_time=60):
        '''Start traffic on Ixia'''

        log.info(banner("Starting L2/L3 traffic"))

        # Start traffic on IxNetwork
        try:
            start_traffic = self.ixNet.execute('start', '/traffic')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        # Verify return
        try:
            assert start_traffic == _PASS
        except AssertionError as e:
            log.error(start_traffic)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Started L2/L3 traffic on device '{}'".\
                        format(self.device.name))

        # Wait after starting L2/L3 traffic for streams to converge to steady state
        log.info("Waiting for '{}' seconds after after starting L2/L3 traffic "
                 "for streams to converge to steady state...".format(wait_time))
        time.sleep(wait_time)

        # Check if traffic is in 'started' state
        log.info("Checking if traffic is in 'started' state...")
        try:
            assert self._get_current_traffic_state() == 'started'
        except Exception as e:
            raise GenieTgnError("Traffic is not in 'started' state")
        else:
            log.info("Traffic is in 'started' state")


    def stop_traffic(self, wait_time=60):
        '''Stop traffic on Ixia'''

        log.info(banner("Stopping L2/L3 traffic"))

        # Stop traffic on IxNetwork
        try:
            stop_traffic = self.ixNet.execute('stop', '/traffic')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        # Verify result
        try:
            assert stop_traffic == _PASS
        except AssertionError as e:
            log.error(stop_traffic)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Stopped L2/L3 traffic on device '{}'".\
                        format(self.device.name))

        # Wait after starting L2/L3 traffic for streams to converge to steady state
        log.info("Waiting for '{}' seconds after after stopping L2/L3 "
                 "traffic...".format(wait_time))
        time.sleep(wait_time)

        # Check if traffic is in 'stopped' state
        log.info("Checking if traffic is in 'stopped' state...")
        try:
            assert self._get_current_traffic_state() == 'stopped'
        except Exception as e:
            raise GenieTgnError("Traffic is not in 'stopped' state")
        else:
            log.info("Traffic is in 'stopped' state")


    def clear_statistics(self, wait_time=10):
        '''Clear all traffic, port, protocol statistics on Ixia'''

        log.info(banner("Clearing traffic statistics"))

        log.info("Clearing all statistics...")
        try:
            clear_stats = self.ixNet.execute('clearStats')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to clear traffic statistics") from e
        else:
            log.info("Successfully cleared traffic statistics on device '{}'".\
                         format(self.device.name))

        log.info("Clearing port statistics...")
        try:
            clear_port_stats = self.ixNet.execute('clearPortsAndTrafficStats')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to clear port statistics") from e
        else:
            log.info("Successfully cleared port statistics on device '{}'".\
                         format(self.device.name))

        log.info("Clearing protocol statistics...")
        try:
            clear_protocol_stats = self.ixNet.execute('clearProtocolStats')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to clear protocol statistics") from e
        else:
            log.info("Successfully cleared protocol statistics on device '{}'".\
                         format(self.device.name))

        # Wait after clearing statistics
        log.info("Waiting for '{}' seconds after clearing statistics".\
                    format(wait_time))
        time.sleep(wait_time)


    def create_genie_statistics_view(self, view_create_interval=30, view_create_iteration=10):
        '''Creates a custom TCL View named "Genie" with the required stats data'''

        log.info(banner("Creating new custom IxNetwork traffic statistics view 'GENIE'"))

        # Delete any previously created TCL Views called "GENIE"
        log.info("Deleting any existing traffic statistics view 'GENIE'...")
        try:
            for view in self.ixNet.getList('/statistics', 'view'):
                if self.ixNet.getAttribute(view, '-caption') == 'GENIE':
                    self.ixNet.remove(view)
                    self.ixNet.commit()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to delete any previously created "
                                "traffic statistics view named 'GENIE'.") from e

        # Check if 'Traffic Items' filter present, if not, add it
        log.info("Checking if 'Traffic Items' filter is found...")
        try:
            ti_added = False
            for ti in self.ixNet.getList('/traffic', 'trafficItem'):
                trackByList = self.ixNet.getAttribute(ti + '/tracking', '-trackBy')
                if 'trackingenabled0' in trackByList:
                    continue
                else:
                    ti_added = True
                    # Traffic Item filter is not found, manually add
                    if self._get_current_traffic_state() != 'stopped' and self._get_current_traffic_state() != 'unapplied':
                        self.stop_traffic(wait_time=15)
                    #self.ixNet.setAttribute(ti, '-tracking', 'trackingenabled0')
                    trackByList.append('trackingenabled0')
                    self.ixNet.setMultiAttribute(ti + '/tracking', '-trackBy', trackByList)
            if ti_added:
                self.ixNet.commit()
                self.apply_traffic(wait_time=15)
                self.start_traffic(wait_time=15)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error adding 'Traffic Items' filer to "
                                "'flow tracking' for traffic items") from e

        # Check if 'Source/Dest Port Pair' filter present, if not, add it
        log.info("Checking if 'Source/Dest Port Pair' filter is found for traffic items...")
        try:
            src_dest_added = False
            for ti in self.ixNet.getList('/traffic', 'trafficItem'):
                trackByList = self.ixNet.getAttribute(ti + '/tracking', '-trackBy')
                if 'sourceDestPortPair0' in trackByList:
                    continue
                else:
                    # Source/Dest Port Pair filter is not found, manually add
                    src_dest_added = True
                    if self._get_current_traffic_state() != 'stopped' and self._get_current_traffic_state() != 'unapplied':
                        self.stop_traffic(wait_time=15)
                    trackByList.append('sourceDestPortPair0')
                    self.ixNet.setMultiAttribute(ti + '/tracking', '-trackBy', trackByList)

            if src_dest_added:
                self.ixNet.commit()
                self.apply_traffic(wait_time=15)
                self.start_traffic(wait_time=15)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error adding 'Source/Dest port Pair' filer to "
                                "'flow tracking' for traffic items") from e

        # Create a new TCL View called "GENIE"
        try:
            self._genie_view = self.ixNet.add(self.ixNet.getRoot() + '/statistics', 'view')
            self.ixNet.setAttribute(self._genie_view, '-caption', 'GENIE')
            self.ixNet.setAttribute(self._genie_view, '-type', 'layer23TrafficFlow')
            self.ixNet.setAttribute(self._genie_view, '-visible', 'true')
            self.ixNet.commit()
            self._genie_view = self.ixNet.remapIds(self._genie_view)
            self._genie_view = self._genie_view[0]
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to create new traffic statistics view "
                                "named 'GENIE'.") from e

        # Populate traffic stream statistics in new TCL View 'GENIE'
        log.info("Populating custom IxNetwork traffic statistics view 'GENIE'...")
        try:
            # Get available traffic items, port filters
            avail_traffic_items = self.ixNet.getList(self._genie_view, 'availableTrafficItemFilter')
            avail_port_filter_list = self.ixNet.getList(self._genie_view, 'availablePortFilter')
            layer23_traffic_flow_filter = self.ixNet.getList(self._genie_view, 'layer23TrafficFlowFilter')

            # Set attributes
            self.ixNet.setAttribute(self._genie_view+'/layer23TrafficFlowFilter', '-trafficItemFilterIds', avail_traffic_items)
            self.ixNet.setAttribute(self._genie_view+'/layer23TrafficFlowFilter', '-portFilterIds', avail_port_filter_list)
            #self.ixNet.setAttribute(self._genie_view+'/layer23TrafficFlowFilter', '-egressLatencyBinDisplayOption', 'showIngressRows')

            # RemapIds
            self._genie_view = self.ixNet.remapIds(self._genie_view)[0]

            # Add specified columns to TCL view
            availableStatList = self.ixNet.getList(self._genie_view, 'statistic')
            for statName in ["Frames Delta",
                             "Tx Frames",
                             "Rx Frames",
                             "Loss %",
                             "Tx Frame Rate",
                             "Rx Frame Rate"]:
                stat = self._genie_view + '/statistic:' + '"{}"'.format(statName)
                if stat in availableStatList:
                    self.ixNet.setAttribute(stat, '-enabled', 'true')
                    self.ixNet.commit()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to add Tx/Rx Frame Rate, Loss %, Frames"
                        " delta data to 'GENIE' traffic statistics view") from e

        # Add 'Source/Dest Port Pair' data to 'GENIE' view
        log.info("Add 'Source/Dest Port Pair' data to 'GENIE' traffic statistics view...")
        try:
            # Create and set enumerationFilter to descending
            enumerationFilter = self.ixNet.add(self._genie_view+'/layer23TrafficFlowFilter', 'enumerationFilter')
            self.ixNet.setAttribute(enumerationFilter, '-sortDirection', 'descending')
            self.ixNet.commit()

            # Add 'Source/Dest Port Pair' column to TCL view (extracted through trackingFilterIds)
            source_dest_track_id = None
            trackingFilterIdList = self.ixNet.getList(self._genie_view, 'availableTrackingFilter')

            # Find the 'Source/Dest Port Pair' object, add it to the 'GENIE' view
            for track_id in trackingFilterIdList:
                if re.search('Source/Dest Port Pair', track_id):
                    source_dest_track_id = track_id
                    break
            if source_dest_track_id:
                self.ixNet.setAttribute(enumerationFilter, '-trackingFilterId', source_dest_track_id)
                self.ixNet.commit()
            else:
                raise GenieTgnError("Unable to add 'Source/Dest Port Pair' to "
                                    "'GENIE' traffic statistics view.")
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to add 'Source/Dest Port Pair' to "
                                "'GENIE' traffic statistics view.") from e

        # Enable 'GENIE' view visibility
        log.info("Enable custom IxNetwork traffic statistics view 'GENIE'...")
        try:
            # Re-enable TCL View "GENIE"
            self.ixNet.setAttribute(self._genie_view, '-enabled', 'true')
            self.ixNet.setAttribute(self._genie_view, '-visible', 'true')
            self.ixNet.commit()

            # Print to log
            log.info("Populated traffic statistics view 'GENIE' with required "
                     "data.")
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while enabling traffic statistics view "
                                "'GENIE' with required data.") from e

        # Create Genie Page object to parse later
        log.info("Displaying custom IxNetwork traffic statistics view 'GENIE' page...")
        try:
            # Get the page view of the TCL View "GENIE"
            self._genie_page = self.ixNet.getList(self._genie_view, 'page')[0]
            self.ixNet.setAttribute(self._genie_page, '-egressMode', 'conditional')
            self.ixNet.commit()

            # Poll until the view is ready
            for i in range(0, view_create_iteration):
                try:
                    assert self.ixNet.getAttribute(self._genie_page, '-isReady') == 'true'
                except Exception as e:
                    log.warning("IxNetwork traffic statistics view 'GENIE' is "
                                "not ready.\nSleeping {} seconds and before "
                                "checking traffic statistics view 'GENIE'")
                    time.sleep(view_create_interval)
                else:
                    log.info("Custom IxNetwork traffic statistics view 'GENIE' "
                             "is ready.")
                    break
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to create custom IxNetwork traffic "
                                "statistics view 'GENIE' page.") from e


    def check_traffic_loss(self, max_outage=120, loss_tolerance=15, rate_tolerance=5, traffic_stream='', display_count=0):
        '''
            For each traffic stream configured on Ixia:
                * 1- Verify traffic outage (in seconds) is less than tolerance threshold
                * 2- Verify current loss % is less than tolerance threshold
                * 3- Verify difference between Tx Rate & Rx Rate is less than tolerance threshold
        '''

        # Check if traffic_stream passed in is valid/found in configuration
        if not traffic_stream or traffic_stream not in self.get_traffic_streams():
            log.error("WARNING: Traffic stream '{}' not found in"
                      " configuration".format(traffic_stream))
            return

        # Init
        outage_check = False
        loss_check = False
        rate_check = False

        # Get 'GENIE' traffic statistics table containing outage/loss values
        traffic_table = self.create_traffic_streams_table(display=False)

        # Loop over all traffic items in configuration
        for row in traffic_table:

            # Get traffic item
            row.header = False ; row.border = False
            current_stream = row.get_string(fields=["Traffic Item"]).strip()

            # Skip all other streams if stream provided
            if traffic_stream and traffic_stream != current_stream:
                continue

            log.info(banner("Checking traffic item '{}'".format(current_stream)))

            # 1- Verify traffic Outage (in seconds) is less than tolerance threshold
            log.info(" 1. Verify traffic outage (in seconds) is less than tolerance threshold")
            outage = row.get_string(fields=["Outage (seconds)"]).strip()
            if float(outage) <= float(max_outage):
                log.info("    -> Traffic outage of '{o}' seconds is within "
                         "expected maximum outage threshold of '{s}' seconds".\
                         format(o=outage, s=max_outage))
                outage_check = True
            else:
                log.error("    -> Traffic outage of '{o}' seconds is *NOT* within "
                          "expected maximum outage threshold of '{s}' seconds".\
                          format(o=outage, s=max_outage))

            # 2- Verify current loss % is less than tolerance threshold
            log.info(" 2. Verify current loss % is less than tolerance threshold")
            if row.get_string(fields=["Loss %"]).strip() != '':
                loss_percentage = row.get_string(fields=["Loss %"]).strip()
            else:
                loss_percentage = 0

            # Check traffic loss
            if float(loss_percentage) <= float(loss_tolerance):
                log.info("    -> Current traffic loss of {l}% is within"
                         " maximum expected loss tolerance of {t}%".\
                         format(t=loss_tolerance, l=loss_percentage))
                loss_check = True
            else:
                log.error("    -> Current traffic loss of {l}% is *NOT* within"
                         " maximum expected loss tolerance of {t}%".\
                         format(t=loss_tolerance, l=loss_percentage))

            # 3- Verify difference between Tx Rate & Rx Rate is less than tolerance threshold
            log.info(" 3. Verify difference between Tx Rate & Rx Rate is less than tolerance threshold")
            tx_rate = row.get_string(fields=["Tx Frame Rate"]).strip()
            rx_rate = row.get_string(fields=["Rx Frame Rate"]).strip()
            if abs(float(tx_rate) - float(rx_rate)) <= float(rate_tolerance):
                log.info("    -> Difference between Tx Rate '{t}' and Rx Rate"
                         " '{r}' is within expected maximum rate loss"
                         " threshold of '{m}' packets per second".\
                         format(t=tx_rate, r=rx_rate, m=rate_tolerance))
                rate_check = True
            else:
                log.error("    -> Difference between Tx Rate '{t}' and Rx Rate"
                          " '{r}' is *NOT* within expected maximum rate loss"
                          " threshold of '{m}' packets per second".\
                          format(t=tx_rate, r=rx_rate, m=rate_tolerance))

        # If all streams had:
        #   1- No traffic outage beyond threshold
        #   2- No curret loss beyond threshold
        #   3- No frames rate loss
        #   all good, break - else repeat, recheck
        if outage_check and loss_check and rate_check:
            log.info("Traffic outage, loss tolerance and rate tolerance are all"
                     "within maximum expected thresholds for traffic item '{}'".\
                     format(traffic_stream))
            return traffic_table
        else:
            # If this is the first time we failed, display traffic table as
            # caller will be catching the exception and won't be able to print
            # the table. Only print if this is the first time for corner case
            # when *ALL* traffic streams have traffic loss/outage
            if display_count == 0:
                log.info(traffic_table)
            raise GenieTgnError("Traffic outage, loss tolerance or rate tolerance"
                                " is *NOT* within maximum expected thresholds"
                                " for traffic item '{}'".format(traffic_stream))


    def create_traffic_streams_table(self, set_golden=False, clear_stats=False, clear_stats_time=30, view_create_interval=30, view_create_iteration=5, display=True):
        '''Create traffic profile of configured streams on Ixia'''

        # Init
        traffic_table = prettytable.PrettyTable()

        # If Genie view and page has not been created before, create one
        if not self._genie_view or not self._genie_page:
            self.create_genie_statistics_view(view_create_interval=view_create_interval,
                                              view_create_iteration=view_create_iteration)

        # Clear stats and wait
        if clear_stats:
            self.clear_statistics(wait_time=clear_stats_time)

        try:
            # Traffic table headers
            headers = self.ixNet.getAttribute(self._genie_page, '-columnCaptions')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get Column Captions from custom view 'GENIE'")

        # Add column for Outage
        headers.append('Outage (seconds)')
        # Arrange data to fit into table as required in final format:
        # ['Source/Dest Port Pair', 'Traffic Item', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Tx Frame Rate', 'Rx Frame Rate', 'Loss %', 'Outage (seconds)']
        del headers[0]
        headers[1], headers[0] = headers[0], headers[1]
        headers[5], headers[7] = headers[7], headers[5]
        headers[6], headers[5] = headers[5], headers[6]
        traffic_table.field_names = headers

        try:
            # Check that all the expected headers were found
            assert headers == ['Source/Dest Port Pair', 'Traffic Item',
                               'Tx Frames', 'Rx Frames', 'Frames Delta',
                               'Tx Frame Rate', 'Rx Frame Rate', 'Loss %',
                               'Outage (seconds)']
        except AssertionError as e:
            raise GenieTgnError("Incorrect headers extracted from custom view 'GENIE'")

        try:
            # Add rows with data
            for item in self.ixNet.getAttribute(self._genie_page, '-rowValues'):
                # Get row value data
                row_item = item[0]
                # Arrange data to fit into table as required in final format:
                # ['Source/Dest Port Pair', 'Traffic Item', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Tx Frame Rate', 'Rx Frame Rate', 'Loss %', 'Outage (seconds)']
                del row_item[0]
                row_item[1], row_item[0] = row_item[0], row_item[1]
                row_item[5], row_item[7] = row_item[7], row_item[5]
                row_item[6], row_item[5] = row_item[5], row_item[6]
                # Calculate outage in seconds from 'Frames Delta' and add to row
                frames_delta = row_item[4]
                tx_frame_rate = row_item[5]
                if tx_frame_rate == '0.000' or tx_frame_rate == '0':
                    outage_seconds = 0.0
                else:
                    outage_seconds = round(float(frames_delta)/float(tx_frame_rate), 3)
                row_item.append(str(outage_seconds))
                # Add data to traffic_table
                traffic_table.add_row(row_item)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get data from custom view 'GENIE'")

        # Align and print profile table in the logs
        traffic_table.align = "l"
        if display:
            log.info(traffic_table)

        # If flag set, reset the golden profile
        if set_golden:
            log.info("\nSetting golden traffic profile\n")
            self._golden_profile = traffic_table

        # Return profile table to caller
        return traffic_table


    def compare_traffic_profile(self, profile1, profile2, loss_tolerance=5, rate_tolerance=2):
        '''Compare two Ixia traffic profiles'''

        log.info(banner("Comparing traffic profiles"))

        # Check profile1
        if not isinstance(profile1, prettytable.PrettyTable) or not profile1.field_names:
            raise GenieTgnError("Profile1 is not in expected format or missing data")
        else:
            log.info("Profile1 is in expected format with data")

        # Check profile2
        if not isinstance(profile2, prettytable.PrettyTable) or not profile2.field_names:
            raise GenieTgnError("Profile2 is not in expected format or missing data")
        else:
            log.info("Profile2 is in expected format with data")

        # Compare both profiles

        # Check number of traffic items provided are the same
        profile1_ti = 0 ; profile2_ti = 0
        for row in profile1:
            if row.get_string(fields=['Traffic Item']):
                profile1_ti += 1
        for row in profile2:
            if row.get_string(fields=['Traffic Item']):
                profile2_ti += 1
        if profile2_ti != profile1_ti:
            raise GenieTgnError("Profiles do not have the same traffic items")

        # Traffic profile column headers
        # ['Source/Dest Port Pair', 'Traffic Item', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Tx Frame Rate', 'Rx Frame Rate', 'Loss %', 'Outage (seconds)']
        names = ['src_dest_pair', 'traffic_item', 'tx_frames', 'rx_frames', 'frames_delta', 'tx_rate', 'rx_rate', 'loss', 'outage']

        # Begin comparison between profiles
        compare_profile_failed = False
        for profile1_row, profile2_row in zip(profile1, profile2):
            profile1_row.header = False ; profile2_row.header = False
            profile1_row_values = {} ; profile2_row_values = {}
            for item, name in zip(profile1_row._rows[0], names):
                profile1_row_values[name] = item
            for item, name in zip(profile2_row._rows[0], names):
                profile2_row_values[name] = item

            # Ensure profiles have traffic data/content
            if profile1_row_values and profile2_row_values:
                # Compare traffic profiles
                if profile1_row_values['src_dest_pair'] == profile2_row_values['src_dest_pair'] and\
                    profile1_row_values['traffic_item'] == profile2_row_values['traffic_item']:

                    # Begin comparison
                    log.info(banner("Comparing profiles for traffic item '{}'".format(profile1_row_values['traffic_item'])))

                    # Compare Tx Frames Rate between two profiles
                    try:
                        assert abs(float(profile1_row_values['tx_rate']) - float(profile2_row_values['tx_rate'])) <= float(rate_tolerance)
                    except AssertionError as e:
                        compare_profile_failed = True
                        log.error("  -> Tx Frames Rate for profile 1 '{p1}' and "
                                  "profile 2 '{p2}' is more than expected "
                                  "tolerance of '{t}'".\
                                  format(p1=profile1_row_values['tx_rate'],
                                         p2=profile2_row_values['tx_rate'],
                                         t=rate_tolerance))
                    else:
                        log.info("  -> Tx Frames Rate difference between "
                                 "profiles is less than threshold of '{}'".\
                                 format(rate_tolerance))

                    # Compare Rx Frames Rate between two profiles
                    try:
                        assert abs(float(profile1_row_values['rx_rate']) - float(profile2_row_values['rx_rate'])) <= float(rate_tolerance)
                    except AssertionError as e:
                        compare_profile_failed = True
                        log.error("  -> Rx Frames Rate for profile 1 '{p1}' and"
                                  " profile 2 '{p2}' is more than expected "
                                  "tolerance of '{t}'".\
                                  format(p1=profile1_row_values['rx_rate'],
                                         p2=profile2_row_values['rx_rate'],
                                         t=rate_tolerance))
                    else:
                        log.info("  -> Rx Frames Rate difference between "
                                 "profiles is less than threshold of '{}'".\
                                 format(rate_tolerance))

                    # Check if loss % in profile1 is not ''
                    try:
                        float(profile1_row_values['loss'])
                    except ValueError:
                        profile1_row_values['loss'] = 0
                    # Check if loss % in profile2 is not ''
                    try:
                        float(profile2_row_values['loss'])
                    except ValueError:
                        profile2_row_values['loss'] = 0
                    # Compare Loss % between two profiles
                    try:
                        assert abs(float(profile1_row_values['loss']) - float(profile2_row_values['loss'])) <= float(loss_tolerance)
                    except AssertionError as e:
                        compare_profile_failed = True
                        log.error("  -> Loss % for profile 1 '{p1}' and "
                                  "profile 2 '{p2}' is more than expected "
                                  "tolerance of '{t}'".\
                                  format(p1=profile1_row_values['loss'],
                                         p2=profile2_row_values['loss'],
                                         t=loss_tolerance))
                    else:
                        log.info("  -> Loss % difference between profiles "
                                 "is less than threshold of '{}'".\
                                 format(loss_tolerance))
                else:
                    log.error("WARNING: The source/dest port pair and traffic"
                              " item are mismatched - skipping check")
            else:
                raise GenieTgnError("Profiles provided for comparison do not "
                                    "contain relevant traffic data")
        # Final result of comparison
        if compare_profile_failed:
            raise GenieTgnError("Comparison failed for traffic items between profiles")
        else:
            log.info("Comparison passed for all traffic items between profiles")


    def set_ixia_virtual_ports(self):
        '''Set virtual Ixia ports for this configuration'''

        try:
            # Set virtual Ixia ports
            self.virtual_ports = self.ixNet.getList(self.ixNet.getRoot(), 'vport')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get virtual ports on Ixia")


    def get_ixia_virtual_port(self, port_name):
        '''Return virtual Ixia port object from port_name'''

        # Set virtual Ixia ports if not previously set
        if not self.virtual_ports:
            self.set_ixia_virtual_ports()

        # Get vport object from port_name
        for item in self.virtual_ports:
            if port_name == self.get_ixia_virtual_port_attribute(item, 'name'):
                return item


    def get_ixia_virtual_port_attribute(self, vport, attribute):
        '''Get attibute for virtual Ixia port'''

        try:
            # Extract Ixia virtual port settings/attribute
            value = self.ixNet.getAttribute(vport, '-{}'.format(attribute))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get attribute '{a}'' for ixia"
                                " port '{p}'".format(a=attribute, p=vport))
        else:
            return value


    def get_traffic_streams(self):
        '''Get traffic streams present in current configuration from "Traffic Item Statistics" '''

        # Init
        traffic_stream_names = []

        # Get traffic streams from Ixia
        try:
            traffic_items = self.ixNet.execute('getColumnValues',
                        '::ixNet::OBJ-/statistics/view:"Traffic Item Statistics"',
                        'Traffic Item')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving traffic items from"
                                " 'Traffic Item Statistics'")

        # Create list
        for item in traffic_items:
            traffic_stream_names.append(item)

        # Return to caller
        return traffic_stream_names


    def get_traffic_stream_data(self, traffic_stream, traffic_data_field):
        '''Get specific data field for specific traffic stream from "Traffic Item Statistics" '''

        # Get all stream data for given traffic_stream
        try:
            return self.ixNet.execute('getValue', 
                    '::ixNet::OBJ-/statistics/view:"Traffic Item Statistics"',
                    traffic_stream, traffic_data_field)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving '{data}' for traffic "
                                "stream '{stream}' from 'Traffic Item Statistics'".\
                                format(data=traffic_data_field, stream=traffic_stream))


    def set_traffic_stream_data(self, traffic_stream, config_field, config_value):
        '''Set specified configuration element for a traffic stream'''

        # Change value for the stream
        try:
            self.ixNet.setAttribute(traffic_stream, '-{}'.format(config_field), config_value)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while setting attribute '{data}' for traffic "
                                "stream '{stream}' from 'Traffic Item Statistics'".\
                                format(data=config_field, stream=traffic_stream))

        # Verify that configuration value for the stream has changed
        try:
            assert config_value == self.get_traffic_stream_data(
                                            traffic_stream=traffic_stream, 
                                            traffic_data_field=config_field)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("'{f}' configuration not updated for '{s}'".\
                            format(f=config_field, s=traffic_stream))


    #--------------------------------------------------------------------------#
    #                           Packet Capture                                 #
    #--------------------------------------------------------------------------#

    def get_ixia_virtual_port_capture(self, port_name):

        # Get virtual Ixia port object
        try:
            vportObj = self.get_ixia_virtual_port(port_name=port_name)
        except:
            raise GenieTgnError("Unable to get virtual Ixia port object for "
                                "port '{}'".format(port_name))

        # Get captureObj for this virtual port
        try:
            return self.ixNet.getList(vportObj, 'capture')[0]
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get captureObj for port '{}'".\
                                format(port_name))


    def enable_data_packet_capture(self, ports):
        '''Enable data packet capture on ports specified'''

        for port in ports.split(', '):

            # Get virtual Ixia port capture object
            captureObj = self.get_ixia_virtual_port_capture(port_name=port)

            # Enable data packet capture on port/node
            log.info("Enabling data packet capture on port '{}'".format(port))
            try:
                self.ixNet.setAttribute(captureObj, '-hardwareEnabled', 'true')
                self.ixNet.commit()
            except Exception as e:
                raise GenieTgnError("Error while enabling data packet capture "
                                    "on port '{}'".format(port))


    def disable_data_packet_capture(self, ports):
        '''Disable data packet capture on ports specified'''

        for port in ports.split(', '):

            # Get virtual Ixia port capture object
            captureObj = self.get_ixia_virtual_port_capture(port_name=port)

            # Enable data packet capture on port/node
            log.info("Disabling data packet capture on port '{}'".format(port))
            try:
                self.ixNet.setAttribute(captureObj, '-hardwareEnabled', 'false')
                self.ixNet.commit()
            except Exception as e:
                raise GenieTgnError("Error while enabling data packet capture "
                                    "on port '{}'".format(port))


    def enable_control_packet_capture(self, ports):
        '''Enable data packet capture on ports specified'''

        for port in ports.split(', '):

            # Get virtual Ixia port capture object
            captureObj = self.get_ixia_virtual_port_capture(port_name=port)

            # Enable data packet capture on port/node
            log.info("Enabling control packet capture on port '{}'".format(port))
            try:
                self.ixNet.setAttribute(captureObj, '-softwareEnabled', 'true')
                self.ixNet.commit()
            except Exception as e:
                raise GenieTgnError("Error while enabling data packet capture "
                                    "on port '{}'".format(port))


    def disable_control_packet_capture(self, ports):
        '''Disable data packet capture on ports specified'''

        for port in ports.split(', '):

            # Get virtual Ixia port capture object
            captureObj = self.get_ixia_virtual_port_capture(port_name=port)

            # Enable data packet capture on port/node
            log.info("Disabling data packet capture on port '{}'".format(port))
            try:
                self.ixNet.setAttribute(captureObj, '-softwareEnabled', 'false')
                self.ixNet.commit()
            except Exception as e:
                raise GenieTgnError("Error while enabling data packet capture "
                                    "on port '{}'".format(port))


    def start_packet_capture(self, capture_time=60):
        '''Start capturing packets for a specified amount of time'''

        log.info("Starting packet capture...")
        try:
            # Start capturing packets
            self.ixNet.execute('startCapture')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start packet capture")

        # Time to wait after capturing packets
        log.info("Waiting for '{}' seconds after starting packet capture".\
                                                        format(capture_time))
        time.sleep(capture_time)


    def stop_packet_capture(self):
        '''Stop capturing packets'''

        log.info("Stopping packet capture...")
        try:
            # Start capturing packets
            self.ixNet.execute('stopCapture')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start packet capture")


    def get_packet_capture_count(self, port_name, pcap_type):
        ''' Get the total count of packets captured during packet capture'''

        # Verify user has provided correct packet type to count
        assert pcap_type in ['data', 'control']

        # Get virtual Ixia port capture object
        captureObj = self.get_ixia_virtual_port_capture(port_name=port_name)

        if pcap_type == 'control':

            log.info("Getting total count of Control Packets...")
            try:
                packet_count = self.ixNet.getAttribute(captureObj, '-controlPacketCounter')
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while getting total contol packets"
                                    " during packet capture")
            else:
                return packet_count

        elif pcap_type == 'data':

            log.info("Getting total count of Data Packets...")
            try:
                packet_count = self.ixNet.getAttribute(captureObj, '-dataPacketCounter')
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while getting total contol packets"
                                    " during packet capture")
            else:
                return packet_count


    def get_packet_capture_data(self, port_name):
        '''Search inside packet collected from pcap for specific data'''

        # Get virtual Ixia port capture object
        captureObj = self.get_ixia_virtual_port_capture(port_name=port_name)

        # Get current packet stack
        log.info("Getting packet capture stack on port '{}".format(port_name))
        try:
            current_packet = self.ixNet.getList(captureObj, 'currentPacket')[0]
            status = self.ixNet.execute('getPacketFromDataCapture', current_packet, 11)
            stacklist = self.ixNet.getList(current_packet, 'stack')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while getting packet capture stack")

        # Get information inside packet capture stack
        log.info("Extracting packet capture data")

        for stack in stacklist:
            try:
                # Get name of stack
                stack_name = self.ixNet.getAttribute(stack, "-displayName")
                log.info(banner(stack_name))

                # List of all the elements within data capture
                for field in self.ixNet.getList(stack, 'field'):
                    # Get the value of the field
                    name = self.ixNet.getAttribute(field, "-displayName")
                    value = self.ixNet.getAttribute(field, "-fieldValue")
                    log.info("{n} : {v}".format(n=name, v=value))
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while extracting data of packet capture")


    def save_packet_capture_file(self, port_name, pcap_type, filename, directory='C:/Results'):
        '''Save packet capture file as specified filename to desired location'''

        # Verify user has provided correct packet type to count
        assert pcap_type in ['data', 'control']

        pcap_dict = {
            'data': 'HW',
            'control': 'SW',
            }

        log.info("Saving packet capture file...")
        try:
            # Save file to C:
            assert self.ixNet.execute('saveCapture', directory, '_{}'.\
                                                format(filename)) == _PASS
        except AssertionError as e:
            log.info(e)
            raise GenieTgnError("Unable to save packet capture file as '{}'".\
                                                            format(filename))

        # Return pcap file to caller
        return 'C:/Results/{port_name}_{pcap}_{f}.cap'.\
            format(port_name=port_name, pcap=pcap_dict[pcap_type], f=filename)


    def export_packet_capture_file(self, src_file, dest_file):
        '''Export packet capture file as specified filename to desired location'''

        log.info("Exporting packet capture file...")
        try:
            self.ixNet.execute('copyFile',
                               self.ixNet.readFrom(src_file, '-ixNetRelative'),
                               self.ixNet.writeTo(dest_file, '-overwrite'))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to copy '{s}' to '{d}'".\
                                                format(s=src_file, d=dest_file))


    #--------------------------------------------------------------------------#
    #                           Stream Config                                  #
    #--------------------------------------------------------------------------#

    def start_traffic_stream(self, traffic_stream, wait_time=15):
        '''Start specific traffic item/stream name on Ixia'''

        log.info(banner("Starting L2/L3 traffic for traffic stream '{}'".\
                        format(traffic_stream)))

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        try:
            # Start traffic for this stream
            self.ixNet.execute('startStatelessTraffic', tiObj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while starting traffic for traffic"
                                " stream '{}'".format(traffic_stream))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after starting traffic stream"
                 " '{s}'".format(t=wait_time, s=traffic_stream))
        time.sleep(wait_time)

        # Ensure the Tx Frame Rate for this stream is not 0 after stopping it
        log.info("Checking Tx Frame Rate for traffic item '{}' is > 0".\
                 format(traffic_stream))
        try:
            assert int(self.\
                get_traffic_stream_data(traffic_stream=traffic_stream,
                                    traffic_data_field='Tx Frame Rate')) > 0
        except AssertionError as e:
            raise GenieTgnError("Tx Frame Rate is not greater than 0 after "
                                "starting traffic for traffic stream '{}'".\
                                format(traffic_stream))
        else:
            log.info("Tx Frame Rate is greater than 0 after starting traffic "
                     "for traffic stream '{}'".format(traffic_stream))


    def stop_traffic_stream(self, traffic_stream, wait_time=15):
        '''Stop specific traffic item/stream name on Ixia'''

        log.info(banner("Stopping L2/L3 traffic for traffic stream '{}'".\
                        format(traffic_stream)))

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        try:
            # Start traffic fo this stream
            self.ixNet.execute('stopStatelessTraffic', tiObj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while starting traffic for traffic"
                                " stream '{}'".format(traffic_stream))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after stopping traffic stream"
                 " '{s}'".format(t=wait_time, s=traffic_stream))
        time.sleep(wait_time)

        # Ensure the Tx Frame Rate for this stream is not 0 after stopping it
        log.info("Checking Tx Frame Rate for traffic item '{}' is = 0".\
                 format(traffic_stream))
        try:
            assert int(self.\
                get_traffic_stream_data(traffic_stream=traffic_stream,
                                    traffic_data_field='Tx Frame Rate')) == 0
        except AssertionError as e:
            raise GenieTgnError("Tx Frame Rate is greater than 0 after "
                                "starting traffic for traffic stream '{}'".\
                                format(traffic_stream))
        else:
            log.info("Tx Frame Rate is 0 after starting traffic for traffic "
                     "stream '{}'".format(traffic_stream))


    def get_traffc_stream_object(self, traffic_stream):
        '''Finds traffic item object from given traffic stream name'''

        log.info("Getting traffic item object for traffic stream '{}'".\
                 format(traffic_stream))

        try:
            for ti in self.ixNet.getList('/traffic', 'trafficItem'):
                if traffic_stream == self.get_traffic_stream_name(traffic_item=ti):
                    return ti
                else:
                    continue
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to find traffic stream '{}' in "
                                "configuration".format(traffic_stream))


    def get_traffic_stream_name(self, traffic_item):
        '''Returns the traffic stream name from a given traffic item object'''

        try:
            return self.ixNet.getAttribute(traffic_item, '-name')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get stream name for traffic item"
                                " '{}'".format())


    def get_flow_groups(self, traffic_stream):
        '''Returns a list of all flow groups for a given traffic stream'''

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        # Get all flow groups
        try:
            return self.ixNet.getList(tiObj, 'highLevelStream')
        except Exception as e:
            raise GenieTgnError("Unable to get list of flow groups for traffic "
                                "stream '{}'".format(traffic_stream))


    def get_flow_group_object(self, traffic_stream, flow_group):
        '''Finds flow group object for the flow group of a given traffic stream'''

        log.info("Getting flow group object for flow group '{f}' of traffic "
                 "stream '{t}'".format(f=flow_group, t=traffic_stream))

        try:
            for group in self.get_flow_groups(traffic_stream=traffic_stream):
                if flow_group == self.get_flow_group_name(flow_group=group):
                    return group
                else:
                    continue
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to find flow group '{f}' for traffic "
                                "stream '{t}' in configuration".\
                                format(traffic_stream))


    def get_flow_group_name(self, flow_group):
        '''Returns the flow group name from a given flow group object'''

        try:
            return self.ixNet.getAttribute(flow_group, '-name')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get flow group name for flow group item"
                                " '{}'".format())


    def generate_traffic_stream(self, traffic_stream, wait_time=15):
        '''Generate traffic for a given traffic item'''

        log.info(banner("Generating traffic for traffic stream '{}'".\
                        format(traffic_stream)))

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        try:
            # Generate traffic
            self.ixNet.execute('generate', tiObj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while generating traffic for traffic "
                                "stream '{}'".format(traffic_stream))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after generating traffic stream"
                 " '{s}'".format(t=wait_time, s=traffic_stream))
        time.sleep(wait_time)


        # Check if traffic is in 'unapplied' state
        log.info("Checking if traffic is in 'unapplied' state...")
        try:
            assert self._get_current_traffic_state() == 'unapplied'
        except Exception as e:
            raise GenieTgnError("Traffic is not in 'unapplied' state")
        else:
            log.info("Traffic is in 'unapplied' state")


    def set_line_rate(self, traffic_stream, rate, flow_group='', stop_traffic_time=15, generate_traffic_time=15, apply_traffic_time=15, start_traffic_time=15):
        '''Set the line rate for given traffic stream or given flow group of a traffic stream'''

        # Check rate provided is not more than 100 as line rate is a percentage
        try:
            assert rate in range(100)
        except AssertionError as e:
            raise GenieTgnError("Invalid input rate={} provided. Line rate must"
                                " be between 0 to 100%".format(rate))

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        if flow_group:
            # Set the line rate for given flow group of this traffic item
            log.info(banner("Setting flow group '{f}' of traffic stream '{t}' "
                            "line rate to '{r}'".format(f=flow_group,
                                                        t=traffic_stream,
                                                        r=rate)))

            # Get flow group object of the given traffic stream
            flowgroupObj = self.get_flow_group_object(traffic_stream=traffic_stream, flow_group=flow_group)

            # Change the line rate as required
            try:
                self.ixNet.setMultiAttribute(flowgroupObj + '/frameRate',
                                             '-rate', rate,
                                             '-type', 'percentLineRate')
                self.ixNet.commit()
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while changing flow group '{f}' of "
                                    "traffic stream '{t}' line rate to '{r}'".\
                                    format(f=flow_group, t=traffic_stream, r=rate))
            else:
                log.info("Successfully changed flow group '{f}' of traffic "
                         "stream '{t}' line rate to '{r}'".format(f=flow_group,
                                                                  t=traffic_stream,
                                                                  r=rate))
        else:
            # Set the line rate for the entire traffic stream
            log.info(banner("Setting traffic stream '{t}' line rate to '{r}'".\
                            format(t=traffic_stream, r=rate)))

            # Stop traffic for the given stream
            self.stop_traffic(wait_time=stop_traffic_time)

            # Get config element object
            try:
                config_elements = self.ixNet.getList(tiObj, "configElement")
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get config elements for traffic "
                                    "stream '{}'".format(traffic_stream))

            for config_element in config_elements:
                try:
                    self.ixNet.setMultiAttribute(config_element + "/frameRate",
                                                 '-rate', rate,
                                                 '-type', 'percentLineRate')
                    self.ixNet.commit()
                except Exception as e:
                    log.error(e)
                    raise GenieTgnError("Error while changing traffic stream "
                                        "'{t}' line rate to '{r}'".\
                                        format(t=traffic_stream, r=rate))
                else:
                    log.info("Successfully changed traffic stream '{t}' line "
                             "rate to '{r}'".format(t=traffic_stream, r=rate))

            # Generate traffic
            self.generate_traffic_stream(traffic_stream=traffic_stream, wait_time=generate_traffic_time)

            # Apply traffic
            self.apply_traffic(wait_time=apply_traffic_time)

            # Start traffic
            self.start_traffic(wait_time=start_traffic_time)


    def set_packet_rate(self, traffic_stream, rate, flow_group='', stop_traffic_time=15, generate_traffic_time=15, apply_traffic_time=15, start_traffic_time=15):
        '''Set the packet rate for given traffic stream or given flow group of a traffic stream'''

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        if flow_group:
            # Set the packet rate for given flow group of this traffic item
            log.info(banner("Setting flow group '{f}' of traffic stream '{t}' "
                            "packet rate to '{r}'".format(f=flow_group,
                                                          t=traffic_stream,
                                                          r=rate)))

            # Get flow group object of the given traffic stream
            flowgroupObj = self.get_flow_group_object(traffic_stream=traffic_stream, flow_group=flow_group)

            # Change the packet rate as required
            try:
                self.ixNet.setMultiAttribute(flowgroupObj + '/frameRate',
                                             '-rate', rate,
                                             '-type', 'framesPerSecond')
                self.ixNet.commit()
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while changing flow group '{f}' of "
                                    "traffic stream '{t}' packet rate to '{r}'".\
                                    format(f=flow_group, t=traffic_stream, r=rate))
            else:
                log.info("Successfully changed flow group '{f}' of traffic "
                         "stream '{t}' packet rate to '{r}'".format(f=flow_group,
                                                                  t=traffic_stream,
                                                                  r=rate))
        else:
            # Set the packet rate for the entire traffic stream
            log.info(banner("Setting traffic stream '{t}' packet rate to '{r}'".\
                            format(t=traffic_stream, r=rate)))

            # Stop traffic for the given stream
            self.stop_traffic(wait_time=stop_traffic_time)

            # Get config element object
            try:
                config_elements = self.ixNet.getList(tiObj, "configElement")
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get config elements for traffic "
                                    "stream '{}'".format(traffic_stream))

            for config_element in config_elements:
                try:
                    self.ixNet.setMultiAttribute(config_element + "/frameRate",
                                                 '-rate', rate,
                                                 '-type', 'framesPerSecond')
                    self.ixNet.commit()
                except Exception as e:
                    log.error(e)
                    raise GenieTgnError("Error while changing traffic stream "
                                        "'{t}' packet rate to '{r}'".\
                                        format(t=traffic_stream, r=rate))
                else:
                    log.info("Successfully changed traffic stream '{t}' packet "
                             "rate to '{r}'".format(t=traffic_stream, r=rate))

            # Generate traffic
            self.generate_traffic_stream(traffic_stream=traffic_stream, wait_time=generate_traffic_time)

            # Apply traffic
            self.apply_traffic(wait_time=apply_traffic_time)

            # Start traffic
            self.start_traffic(wait_time=start_traffic_time)


    def set_layer2_bit_rate(self, traffic_stream, rate, rate_unit, flow_group='', stop_traffic_time=15, generate_traffic_time=15, apply_traffic_time=15, start_traffic_time=15):
        '''Set the Layer2 bit rate for given traffic stream or given flow group
           within the traffic stream'''

        # Define units_dict
        units_dict = {
            'bps': 'bitsPerSec',
            'Kbps': 'kbitsPerSec',
            'Mbps': 'mbitsPerSec',
            'Bps': 'bytesPerSec',
            'KBps': 'kbytesPerSec',
            'MBps': 'mbytesPerSec',
        }

        # Verify valid units have been passed in
        try:
            assert rate_unit in ['bps', 'Kbps', 'Mbps', 'Bps', 'KBps', 'MBps']
        except AssertionError as e:
            raise GenieTgnError("Invalid unit '{}' passed in for layer2 bit rate".\
                                format(rate_unit))

        # Get traffic item object from stream name
        tiObj = self.get_traffc_stream_object(traffic_stream=traffic_stream)

        if flow_group:
            # Set the layer2 bit rate for given flow group of this traffic item
            log.info(banner("Setting flow group '{f}' of traffic stream '{t}' "
                            "layer2 bit rate to '{r}'".format(f=flow_group,
                                                              t=traffic_stream,
                                                              r=rate)))

            # Get flow group object of the given traffic stream
            flowgroupObj = self.get_flow_group_object(traffic_stream=traffic_stream, flow_group=flow_group)

            # Change the layer2 bit rate as required
            try:
                self.ixNet.setMultiAttribute(flowgroupObj + '/frameRate',
                                             '-rate', rate,
                                             '-bitRateUnitsType', units_dict[rate_unit],
                                             '-type', 'bitsPerSecond')
                self.ixNet.commit()
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while changing flow group '{f}' of "
                                    "traffic stream '{t}' layer2 bit rate to"
                                    " '{r}'".format(f=flow_group,
                                                    t=traffic_stream,
                                                    r=rate))
            else:
                log.info("Successfully changed flow group '{f}' of traffic "
                         "stream '{t}' layer2 bit rate to '{r}'".\
                         format(f=flow_group, t=traffic_stream, r=rate))
        else:
            # Set the layer2 bit rate for the entire traffic stream
            log.info(banner("Setting traffic stream '{t}' layer2 bit rate to"
                            " '{r}'".format(t=traffic_stream, r=rate)))

            # Stop traffic for the given stream
            self.stop_traffic(wait_time=stop_traffic_time)

            # Get config element object
            try:
                config_elements = self.ixNet.getList(tiObj, "configElement")
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get config elements for traffic "
                                    "stream '{}'".format(traffic_stream))

            for config_element in config_elements:
                try:
                    self.ixNet.setMultiAttribute(config_element + "/frameRate",
                                                 '-rate', rate,
                                                 '-bitRateUnitsType', units_dict[rate_unit],
                                                 '-type', 'bitsPerSecond')
                    self.ixNet.commit()
                except Exception as e:
                    log.error(e)
                    raise GenieTgnError("Error while changing traffic stream "
                                        "'{t}' layer2 bit rate to '{r}'".\
                                        format(t=traffic_stream, r=rate))
                else:
                    log.info("Successfully changed traffic stream '{t}' layer2 "
                             "bit rate to '{r}'".format(t=traffic_stream, r=rate))

            # Generate traffic
            self.generate_traffic_stream(traffic_stream=traffic_stream, wait_time=generate_traffic_time)

            # Apply traffic
            self.apply_traffic(wait_time=apply_traffic_time)

            # Start traffic
            self.start_traffic(wait_time=start_traffic_time)

