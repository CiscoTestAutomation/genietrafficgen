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
            assert self.get_traffic_attribute(attribute='state') == 'unapplied'
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
            assert self.get_traffic_attribute(attribute='state') == 'stopped'
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

        # Check if traffic is already started
        state = self.get_traffic_attribute(attribute='state')
        running = self.get_traffic_attribute(attribute='isTrafficRunning')
        if state == 'started' or running == 'true':
            log.info("SKIP: Traffic is already running and in 'started' state")
            return

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
            assert self.get_traffic_attribute(attribute='state') == 'started'
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
            assert self.get_traffic_attribute(attribute='state') == 'stopped'
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


    def create_genie_statistics_view(self, view_create_interval=30, view_create_iteration=10, enable_tracking=True, enable_port_pair=True):
        '''Creates a custom TCL View named "Genie" with the required stats data'''

        log.info(banner("Creating new custom IxNetwork traffic statistics view 'GENIE'"))

        # Default statistics to add to custom 'GENIE' traffic statistics view
        default_stats_list = ["Frames Delta",
                              "Tx Frames",
                              "Rx Frames",
                              "Loss %",
                              "Tx Frame Rate",
                              "Rx Frame Rate",
                              ]

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

        # Enable 'Traffic Items' filter if not present
        if enable_tracking:
            self.enable_flow_tracking_filter(tracking_filter='trackingenabled0')

        # Enable 'Source/Dest Port Pair' filter if not present
        if enable_port_pair:
            self.enable_flow_tracking_filter(tracking_filter='sourceDestPortPair0')

        # Create a new TCL View called "GENIE"
        log.info("Creating a new traffic statistics view 'GENIE'")
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
            for statName in default_stats_list:
                log.info("Adding '{}' statistics to 'GENIE' view".format(statName))
                stat = self._genie_view + '/statistic:' + '"{}"'.format(statName)
                if stat in availableStatList:
                    self.ixNet.setAttribute(stat, '-enabled', 'true')
                    self.ixNet.commit()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to add Tx/Rx Frame Rate, Loss %, Frames"
                        " delta data to 'GENIE' traffic statistics view") from e

        # Create and set enumerationFilter to descending
        log.info("Get enumerationFilter to add custom columns to view")
        try:
            # Get enumerationFilter object
            enumerationFilter = self.ixNet.add(self._genie_view+'/layer23TrafficFlowFilter', 'enumerationFilter')
            self.ixNet.setAttribute(enumerationFilter, '-sortDirection', 'descending')
            self.ixNet.commit()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get enumerationFilter object for"
                                " 'GENIE' view") from e

        # Adding 'Source/Dest Port Pair' column to 'GENIE' view
        log.info("Add 'Source/Dest Port Pair' column to 'GENIE' custom traffic statistics view...")
        try:
            # Find the 'Source/Dest Port Pair' object, add it to the 'GENIE' view
            source_dest_track_id = None
            trackingFilterIdList = self.ixNet.getList(self._genie_view, 'availableTrackingFilter')
            for track_id in trackingFilterIdList:
                if re.search('Source/Dest Port Pair', track_id):
                    source_dest_track_id = track_id
                    break
            if source_dest_track_id:
                self.ixNet.setAttribute(enumerationFilter, '-trackingFilterId', source_dest_track_id)
                self.ixNet.commit()
            else:
                raise GenieTgnError("Unable to add column for filter "
                                    "'Source/Dest Port Pair' to 'GENIE' "
                                    "traffic statistics view.")
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


    def enable_flow_tracking_filter(self, tracking_filter):
        '''Enable specific flow tracking filters for traffic streams'''

        # Check valid tracking_filter passed in
        assert tracking_filter in ['trackingenabled0',
                                   'sourceDestPortPair0',
                                   'sourceDestValuePair0',
                                   ]

        # Init
        filter_added = False

        # Mapping for filter names
        map_dict = {
            'trackingenabled0': "'Traffic Items'",
            'sourceDestPortPair0': "'Source/Dest Port Pair'",
            'sourceDestValuePair0': "'Source/Dest Value Pair"
            }

        log.info("Checking if {} filter present in L2L3 traffic streams...".\
                 format(map_dict[tracking_filter]))

        # Get all traffic stream objects in configuration
        for ti in self.get_traffic_stream_objects():

            # Get traffic stream type
            ti_type = None ; ti_name = None
            try:
                ti_type = self.ixNet.getAttribute(ti, '-trafficItemType')
                ti_name = self.ixNet.getAttribute(ti, '-name')
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get traffic item '{}'"
                                    " attributes".format(ti))

            # If traffic streams is not of type 'l2l3' then skip to next stream
            if ti_type != 'l2L3':
                continue

            # Get the status of 'trackingenabled' filter
            try:
                trackByList = self.ixNet.getAttribute(ti + '/tracking', '-trackBy')
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while checking status of filter '{f}'"
                                    " for traffic stream '{t}'".format(t=ti_name,
                                    f=tracking_filter))

            # If tracking_filter is already present then skip to next stream
            if tracking_filter in trackByList:
                continue

            # At this point, tracking_filter is not found, add it manually
            log.info("Adding '{f}' filter to traffic stream '{t}'".\
                     format(f=tracking_filter, t=ti_name))
            filter_added = True

            # Stop the traffic
            state = get_traffic_attribute(attribute='state')
            if state != 'stopped' and state != 'unapplied':
                self.stop_traffic(wait_time=15)

            # Add tracking_filter
            trackByList.append(tracking_filter)
            try:
                self.ixNet.setMultiAttribute(ti + '/tracking', '-trackBy', trackByList)
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Error while adding '{f}' filter to traffic"
                                    " stream '{t}'".format(t=ti_name,
                                    f=tracking_filter))

        # Loop exhausted, if tracking_filter added, commit+apply+start traffic
        if filter_added:
            self.ixNet.commit()
            self.apply_traffic(wait_time=15)
            self.start_traffic(wait_time=15)
        else:
            log.info("Filter '{}' previously configured for all L2L3 traffic "
                     "streams".format(tracking_filter))


    def check_traffic_loss(self, max_outage=120, loss_tolerance=15, rate_tolerance=5, check_iteration=10, check_interval=60, traffic_stream='', outage_dict={}):
        '''Check traffic loss for each traffic stream configured on Ixia
            using statistics/data from 'Traffic Item Statistics' view'''

        # Get and display 'GENIE' traffic statistics table containing outage/loss values
        traffic_table = self.create_traffic_streams_table()
        traffic_streams = self.get_traffic_items_from_genie_view(traffic_table=traffic_table)

        for i in range(check_iteration):

            log.info("\nAttempt #{}: Checking traffic outage/loss for all "
                     "streams".format(i+1))
            outage_check = True

            # Check all streams for traffic outage/loss
            for stream in traffic_streams:

                # Skip other streams if stream provided
                if traffic_stream and stream != traffic_stream:
                    continue

                # Skip checks if traffic stream is not of type l2l3
                ti_type = self.get_traffic_stream_attribute(traffic_stream=stream,
                                                            attribute='trafficItemType')
                if ti_type != 'l2L3':
                    log.warning("SKIP: Traffic stream '{}' is not of type L2L3".\
                                format(stream))
                    continue

                # Skip checks if traffic stream from "GENIE" table not in configuration
                if stream not in self.get_traffic_stream_names():
                    log.warning("SKIP: Traffic stream '{}' not found in "
                                "configuration".format(stream))
                    continue

                # Determine outage values for this traffic stream
                if outage_dict and 'traffic_streams' in outage_dict and \
                    stream in outage_dict['traffic_streams']:
                    outage=outage_dict['traffic_streams'][stream]['max_outage']
                    loss=outage_dict['traffic_streams'][stream]['loss_tolerance']
                    rate=outage_dict['traffic_streams'][stream]['rate_tolerance']
                else:
                    outage=max_outage
                    loss=loss_tolerance
                    rate=rate_tolerance

                # Verify outage for traffic stream
                if not self.verify_traffic_stream_outage(traffic_stream=stream,
                                                         traffic_table=traffic_table,
                                                         max_outage=outage,
                                                         loss_tolerance=loss,
                                                         rate_tolerance=rate):
                    # Traffic loss observed for stream
                    outage_check = False

            # Check if iteration required based on results
            if outage_check:
                log.info("Successfully verified traffic outages/loss is within "
                         "tolerance for all traffic streams")
                break
            elif i == check_iteration or i == check_iteration-1:
                # End of iterations, raise Exception and exit
                raise GenieTgnError("Unexpected traffic outage/loss is observed")
            else:
                # Traffic loss observed, sleep and recheck
                log.error("Sleeping '{s}' seconds and rechecking traffic "
                          "streams for traffic outage/loss".\
                          format(s=check_interval))
                time.sleep(check_interval)


    def verify_traffic_stream_outage(self, traffic_stream, traffic_table, max_outage=120, loss_tolerance=15, rate_tolerance=5):
        '''For each traffic stream configured on Ixia:
            * 1- Verify traffic outage (in seconds) is less than tolerance threshold
            * 2- Verify current loss % is less than tolerance threshold
            * 3- Verify difference between Tx Rate & Rx Rate is less than tolerance threshold
        '''

        log.info(banner("Verifying traffic item '{}'".format(traffic_stream)))

        # Init
        outage_check = False
        loss_check = False
        rate_check = False

        # Loop over all traffic items in configuration
        for row in traffic_table:

            # Get row in table associated with traffic stream
            row.header = False ; row.border = False
            current_stream = row.get_string(fields=["Traffic Item"]).strip()
            if traffic_stream != current_stream:
                continue

            # 1- Verify traffic Outage (in seconds) is less than tolerance threshold
            log.info("1. Verify traffic outage (in seconds) is less than tolerance threshold")
            outage = row.get_string(fields=["Outage (seconds)"]).strip()
            if float(outage) <= float(max_outage):
                log.info("* Traffic outage of '{o}' seconds is within "
                         "expected maximum outage threshold of '{s}' seconds".\
                         format(o=outage, s=max_outage))
                outage_check = True
            else:
                log.error("* Traffic outage of '{o}' seconds is *NOT* within "
                          "expected maximum outage threshold of '{s}' seconds".\
                          format(o=outage, s=max_outage))

            # 2- Verify current loss % is less than tolerance threshold
            log.info("2. Verify current loss % is less than tolerance threshold")
            if row.get_string(fields=["Loss %"]).strip() != '':
                loss_percentage = row.get_string(fields=["Loss %"]).strip()
            else:
                loss_percentage = 0

            # Check traffic loss
            if float(loss_percentage) <= float(loss_tolerance):
                log.info("* Current traffic loss of {l}% is within"
                         " maximum expected loss tolerance of {t}%".\
                         format(t=loss_tolerance, l=loss_percentage))
                loss_check = True
            else:
                log.error("* Current traffic loss of {l}% is *NOT* within"
                          " maximum expected loss tolerance of {t}%".\
                          format(t=loss_tolerance, l=loss_percentage))

            # 3- Verify difference between Tx Rate & Rx Rate is less than tolerance threshold
            log.info("3. Verify difference between Tx Rate & Rx Rate is less than tolerance threshold")
            tx_rate = row.get_string(fields=["Tx Frame Rate"]).strip()
            rx_rate = row.get_string(fields=["Rx Frame Rate"]).strip()
            if abs(float(tx_rate) - float(rx_rate)) <= float(rate_tolerance):
                log.info("* Difference between Tx Rate '{t}' and Rx Rate"
                         " '{r}' is within expected maximum rate loss"
                         " threshold of '{m}' packets per second".\
                         format(t=tx_rate, r=rx_rate, m=rate_tolerance))
                rate_check = True
            else:
                log.error("* Difference between Tx Rate '{t}' and Rx Rate"
                          " '{r}' is *NOT* within expected maximum rate loss"
                          " threshold of '{m}' packets per second".\
                          format(t=tx_rate, r=rx_rate, m=rate_tolerance))

            # Checks completed, avoid checking other streams with duplicate names
            break

        # If all streams had:
        #   1- No traffic outage beyond threshold
        #   2- No current loss beyond threshold
        #   3- No frames rate loss
        if outage_check and loss_check and rate_check:
            log.info("Traffic stream '{}': traffic outage, loss% and Tx/Rx Rate"
                     " difference within maximum expected threshold".\
                     format(traffic_stream))
            return True
        else:
            log.error("Traffic stream '{}': traffic outage, loss% and Tx/Rx Rate"
                      " difference *NOT* within maximum expected threshold".\
                      format(traffic_stream))
            return False


    def create_traffic_streams_table(self, set_golden=False, clear_stats=False, clear_stats_time=30, view_create_interval=30, view_create_iteration=5, display=True):
        '''Returns traffic profile of configured streams on Ixia'''

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
                        log.error("* Tx Frames Rate for profile 1 '{p1}' and "
                                  "profile 2 '{p2}' is more than expected "
                                  "tolerance of '{t}'".\
                                  format(p1=profile1_row_values['tx_rate'],
                                         p2=profile2_row_values['tx_rate'],
                                         t=rate_tolerance))
                    else:
                        log.info("* Tx Frames Rate difference between "
                                 "profiles is less than threshold of '{}'".\
                                 format(rate_tolerance))

                    # Compare Rx Frames Rate between two profiles
                    try:
                        assert abs(float(profile1_row_values['rx_rate']) - float(profile2_row_values['rx_rate'])) <= float(rate_tolerance)
                    except AssertionError as e:
                        compare_profile_failed = True
                        log.error("* Rx Frames Rate for profile 1 '{p1}' and"
                                  " profile 2 '{p2}' is more than expected "
                                  "tolerance of '{t}'".\
                                  format(p1=profile1_row_values['rx_rate'],
                                         p2=profile2_row_values['rx_rate'],
                                         t=rate_tolerance))
                    else:
                        log.info("* Rx Frames Rate difference between "
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
                        log.error("* Loss % for profile 1 '{p1}' and "
                                  "profile 2 '{p2}' is more than expected "
                                  "tolerance of '{t}'".\
                                  format(p1=profile1_row_values['loss'],
                                         p2=profile2_row_values['loss'],
                                         t=loss_tolerance))
                    else:
                        log.info("* Loss % difference between profiles "
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


    #--------------------------------------------------------------------------#
    #                               Traffic                                    #
    #--------------------------------------------------------------------------#

    def get_traffic_attribute(self, attribute):
        '''Returns the specified attribute for the given traffic stream'''

        # Sample attributes
        # ['state', 'isApplicationTrafficRunning', 'isTrafficRunning']

        try:
            return self.ixNet.getAttribute('/traffic', '-{}'.format(attribute))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to check attribute '{}'".\
                                format(attribue)) from e


    def get_traffic_items_from_genie_view(self, traffic_table):
        '''Returns list of all traffic items from within the "GENIE" view traffic table'''

        # Init
        traffic_streams = []

        # Loop over traffic table provided
        for row in traffic_table:
            row.header = False
            row.border = False
            traffic_streams.append(row.get_string(fields=["Traffic Item"]).strip())

        # Return to caller
        return traffic_streams


    #--------------------------------------------------------------------------#
    #                           Virtual Ports                                  #
    #--------------------------------------------------------------------------#

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
    #                        Traffic Item (Stream)                             #
    #--------------------------------------------------------------------------#

    def get_traffic_stream_names(self):
        '''Returns a list of all traffic stream names present in current configuration'''

        # Init
        traffic_streams = []

        # Get traffic stream names from Ixia
        try:
            for item in self.get_traffic_stream_objects():
                traffic_streams.append(self.ixNet.getAttribute(item, '-name'))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving traffic streams from "
                                "configuration.")
        else:
            # Return to caller
            return traffic_streams


    def get_traffic_stream_objects(self):
        '''Returns a list of all traffic stream objects present in current configuration'''

        # Get traffic streams from Ixia
        try:
            return self.ixNet.getList('/traffic', 'trafficItem')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving traffic streams from "
                                "configuration.")


    def find_traffic_stream_object(self, traffic_stream):
        '''Finds the given stream name's traffic stream object'''

        # Init
        ti_obj = None

        # Find traffic stream object of the given traffic stream
        for item in self.get_traffic_stream_objects():
            try:
                if self.ixNet.getAttribute(item, '-name') == traffic_stream:
                    ti_obj = item
                    break
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get traffic stream object name")

        # Return to caller
        if ti_obj:
            return ti_obj
        else:
            raise GenieTgnError("Unable to find ::ixNet:: object for traffic "
                                "stream '{}'".format(traffic_stream))


    def get_traffic_stream_attribute(self, traffic_stream, attribute):
        '''Returns the specified attribute for the given traffic stream'''

        # Sample attributes
        # ['name', 'state', 'txPortName', 'txPortId', 'rxPortName', 'rxPortId', 'trafficItemType']

        # Find traffic stream object
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

        # Return the attribute specified for this traffic stream
        try:
            return self.ixNet.getAttribute(ti_obj, '-{}'.format(attribute))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get '{a}' for traffic stream '{t}'".\
                                format(a=attribute, t=traffic_stream))


    def start_traffic_stream(self, traffic_stream, wait_time=15):
        '''Start specific traffic stream on Ixia'''

        log.info(banner("Starting L2/L3 traffic for traffic stream '{}'".\
                        format(traffic_stream)))

        # Find traffic stream object from stream name
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

        try:
            # Start traffic for this stream
            self.ixNet.execute('startStatelessTraffic', ti_obj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while starting traffic for traffic"
                                " stream '{}'".format(traffic_stream))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after starting traffic stream"
                 " '{s}'".format(t=wait_time, s=traffic_stream))
        time.sleep(wait_time)

        # Verify traffic stream state is now 'started'
        log.info("Verify traffic stream '{}' state is now 'started'".\
                 format(traffic_stream))
        try:
            assert 'started' == self.get_traffic_stream_attribute(traffic_stream=traffic_stream, attribute='state')
        except AssertionError as e:
            raise GenieTgnError("Traffic stream '{}' state is not 'started'".\
                                format(traffic_stream))
        else:
            log.info("Traffic stream '{}' state is 'started'".format(traffic_stream))

        # Verify Tx Frame Rate for this stream is > 0 after starting it
        log.info("Verify Tx Frame Rate > 0 for traffic stream '{}'".\
                 format(traffic_stream))
        try:
            assert float(self.get_traffic_items_statistics_data(traffic_stream=traffic_stream, traffic_data_field='Tx Frame Rate')) > 0.0
        except AssertionError as e:
            raise GenieTgnError("Tx Frame Rate is not greater than 0 after "
                                "starting traffic for traffic stream '{}'".\
                                format(traffic_stream))
        else:
            log.info("Tx Frame Rate is greater than 0 after starting traffic "
                     "for traffic stream '{}'".format(traffic_stream))


    def stop_traffic_stream(self, traffic_stream, wait_time=15):
        '''Stop specific traffic stream on Ixia'''

        log.info(banner("Stopping L2/L3 traffic for traffic stream '{}'".\
                        format(traffic_stream)))

        # Find traffic stream object from stream name
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

        try:
            # Stop traffic fo this stream
            self.ixNet.execute('stopStatelessTraffic', ti_obj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while stopping traffic for traffic"
                                " stream '{}'".format(traffic_stream))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after stopping traffic stream"
                 " '{s}'".format(t=wait_time, s=traffic_stream))
        time.sleep(wait_time)

        # Verify traffic stream state is now 'stopped'
        log.info("Verify traffic stream '{}' state is now 'stopped'".\
                 format(traffic_stream))
        try:
            assert 'stopped' == self.get_traffic_stream_attribute(traffic_stream=traffic_stream, attribute='state')
        except AssertionError as e:
            raise GenieTgnError("Traffic stream '{}' state is not 'stopped'".\
                                format(traffic_stream))
        else:
            log.info("Traffic stream '{}' state is 'stopped'".format(traffic_stream))

        # Verify Tx Frame Rate for this stream is > 0 after starting it
        log.info("Verify Tx Frame Rate == 0 for traffic stream '{}'".\
                 format(traffic_stream))
        try:
            assert float(self.get_traffic_items_statistics_data(traffic_stream=traffic_stream, traffic_data_field='Tx Frame Rate')) == 0.0
        except AssertionError as e:
            raise GenieTgnError("Tx Frame Rate is greater than 0 after "
                                "stopping traffic for traffic stream '{}'".\
                                format(traffic_stream))
        else:
            log.info("Tx Frame Rate == 0 after stopping traffic for traffic "
                     "stream '{}'".format(traffic_stream))


    def generate_traffic_stream(self, traffic_stream, wait_time=15):
        '''Generate traffic for a given traffic stream'''

        log.info(banner("Generating L2/L3 traffic for traffic stream '{}'".\
                        format(traffic_stream)))

        # Find traffic stream object from stream name
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

        try:
            # Generate traffic
            self.ixNet.execute('generate', ti_obj)
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
            assert self.get_traffic_attribute(attribute='state') == 'unapplied'
        except Exception as e:
            raise GenieTgnError("Traffic is not in 'unapplied' state")
        else:
            log.info("Traffic is in 'unapplied' state")


    #--------------------------------------------------------------------------#
    #                       Traffic Item Statistics                            #
    #--------------------------------------------------------------------------#

    def get_traffic_items_statistics_data(self, traffic_stream, traffic_data_field):
        '''Get value of traffic_data_field of traffic_tream from "Traffic Item Statistics" '''

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


    #--------------------------------------------------------------------------#
    #                            Flow Groups                                   #
    #--------------------------------------------------------------------------#

    def get_flow_group_names(self, traffic_stream):
        '''Returns a list of all the flow group names for the given traffic stream present in current configuration'''

        # Init
        flow_groups = []

        # Get flow group objects of given traffic stream from Ixia
        try:
            for item in self.get_flow_group_objects():
                flow_groups.append(self.ixNet.getAttribute(item, '-name'))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving flow groups for traffic"
                                " stream '{}' from configuration.".\
                                format(traffic_stream))
        else:
            # Return to caller
            return flow_groups


    def get_flow_group_objects(self, traffic_stream):
        '''Returns a list of flow group objects for the given traffic stream present in current configuration'''

        # Get traffic item object from traffic stream name
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

        # Return list of flow group highLevelStream objects
        try:
            return self.ixNet.getList(ti_obj, 'highLevelStream')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Flow groups not found in configuration for "
                                "traffic stream '{}'".format(traffic_stream))


    def find_flow_group_object(self, traffic_stream, flow_group):
        '''Finds the flow group object when given the flow group name and traffic stream'''

        # Init
        fg_obj = None

        # Get flow group object of the given flow group name and traffic stream
        for item in self.get_flow_group_objects(traffic_stream=traffic_stream):
            try:
                if self.ixNet.getAttribute(item, '-name') == flow_group:
                    fg_obj = item
                    break
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get Quick Flow Group object name")

        # Return to caller
        if fg_obj:
            return fg_obj
        else:
            raise GenieTgnError("Unable to find ::ixNet:: object for Quick "
                                "Flow Group '{}'".format(flow_group))


    def get_flow_group_attribute(self, traffic_stream, flow_group, attribute):
        '''Returns the specified attribute for the given flow group of the traffic stream'''

        # Sample attributes
        # ['name', 'state', 'txPortName', 'txPortId', 'rxPortName', 'rxPortId']

        # Find flow group object
        fg_obj = self.find_flow_group_object(traffic_stream=traffic_stream, flow_group=flow_group)

        # Return the attribute specified for this Quick Flow Group
        try:
            return self.ixNet.getAttribute(fg_obj, '-{}'.format(attribute))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get '{a}' for Quick Flow Group '{f}'".\
                                format(a=attribute, f=flow_group))


    def start_flow_group(self, traffic_stream, flow_group, wait_time=15):
        '''Start given flow group under of traffic stream on Ixia'''

        log.info(banner("Starting traffic for flow group '{}'".\
                        format(flow_group)))

        # Find flow group object from flow group name
        fg_obj = self.find_flow_group_object(traffic_stream=traffic_stream, flow_group=flow_group)

        try:
            # Start traffic for this flow group
            self.ixNet.execute('startStatelessTraffic', fg_obj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while starting traffic for flow group"
                                " '{}'".format(flow_group))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after starting traffic for flow "
                 "group '{f}'".format(t=wait_time, f=flow_group))
        time.sleep(wait_time)

        # Verify flow group state is now 'started'
        log.info("Verify flow group '{}' state is now 'started'".\
                 format(flow_group))
        try:
            assert 'started' == self.get_flow_group_attribute(traffic_stream=traffic_stream, flow_group=flow_group, attribute='state')
        except AssertionError as e:
            raise GenieTgnError("Flow group '{}' state is not 'started'".\
                                format(flow_group))
        else:
            log.info("Flow group '{}' state is 'started'".format(flow_group))


    def stop_flow_group(self, traffic_stream, flow_group, wait_time=15):
        '''Stop given flow group under of traffic stream on Ixia'''

        log.info(banner("Stopping traffic for flow group '{}'".\
                        format(flow_group)))

        # Find flow group object from flow group name
        fg_obj = self.find_flow_group_object(traffic_stream=traffic_stream, flow_group=flow_group)

        try:
            # Stop traffic for this flow group
            self.ixNet.execute('stopStatelessTraffic', fg_obj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while stopping traffic for flow group"
                                " '{}'".format(flow_group))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after stopping traffic for flow "
                 "group '{f}'".format(t=wait_time, f=flow_group))
        time.sleep(wait_time)

        # Verify flow group state is now 'stopped'
        log.info("Verify flow group '{}' state is now 'stopped'".\
                 format(flow_group))
        try:
            assert 'stopped' == self.get_flow_group_attribute(traffic_stream=traffic_stream, flow_group=flow_group, attribute='state')
        except AssertionError as e:
            raise GenieTgnError("Flow group '{}' state is not 'stopped'".\
                                format(flow_group))
        else:
            log.info("Flow group '{}' state is 'stopped'".format(flow_group))


    #--------------------------------------------------------------------------#
    #                          Quick Flow Groups                               #
    #--------------------------------------------------------------------------#

    def get_quick_flow_group_names(self):
        '''Returns a list of all the Quick Flow Group names present in current configuration'''

        # Init
        quick_flow_groups = []

        # Get Quick Flow Group objects from Ixia
        try:
            for item in self.get_quick_flow_group_objects():
                quick_flow_groups.append(self.ixNet.getAttribute(item, '-name'))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving Quick Flow Groups from "
                                "configuration.")
        else:
            # Return to caller
            return quick_flow_groups


    def get_quick_flow_group_objects(self):
        '''Returns a list of all Quick Flow Group objects present in current configuration'''

        # Init
        qfg_traffic_item = None

        # Get Quick Flow Group 'traffic stream' object
        for item in self.get_traffic_stream_objects():
            try:
                if self.ixNet.getAttribute(item, '-name') == 'Quick Flow Groups':
                    qfg_traffic_item = item
                    break
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get Quick Flow Group "
                                    "corresponding 'traffic stream' object")

        # Return list of Quick Flow Group highLevelStream objects
        if qfg_traffic_item:
            try:
                return self.ixNet.getList(qfg_traffic_item, 'highLevelStream')
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Quick Flow Groups not found in configuration")
        else:
            raise GenieTgnError("Quick Flow Groups not found in configuration")


    def find_quick_flow_group_object(self, quick_flow_group):
        '''Finds the Quick Flow Group object when given the Quick Flow Group name'''

        # Init
        qfg_obj = None

        # Get Quick Flow Group object of the given Quick Flow Group name
        for item in self.get_quick_flow_group_objects():
            try:
                if self.ixNet.getAttribute(item, '-name') == quick_flow_group:
                    qfg_obj = item
                    break
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to get Quick Flow Group object name")

        # Return to caller
        if qfg_obj:
            return qfg_obj
        else:
            raise GenieTgnError("Unable to find ::ixNet:: object for Quick "
                                "Flow Group '{}'".format(quick_flow_group))


    def get_quick_flow_group_attribute(self, quick_flow_group, attribute):
        '''Returns the specified attribute for the given Quick Flow Group'''

        # Sample attributes
        # ['name', 'state', 'txPortName', 'txPortId', 'rxPortName', 'rxPortId']

        # Find Quick Flow Group object
        qfg_obj = self.find_quick_flow_group_object(quick_flow_group=quick_flow_group)

        # Return the attribute specified for this Quick Flow Group
        try:
            return self.ixNet.getAttribute(qfg_obj, '-{}'.format(attribute))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get '{a}' for Quick Flow Group '{q}'".\
                                format(a=attribute, q=quick_flow_group))


    def start_quick_flow_group(self, quick_flow_group, wait_time=15):
        '''Start given Quick Flow Group on Ixia'''

        log.info(banner("Starting traffic for Quick Flow Group '{}'".\
                        format(quick_flow_group)))

        # Find flow group object from flow group name
        qfg_obj = self.find_quick_flow_group_object(quick_flow_group=quick_flow_group)

        try:
            # Start traffic for this Quick Flow Group
            self.ixNet.execute('startStatelessTraffic', qfg_obj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while starting traffic for Quick Flow "
                                "Group '{}'".format(quick_flow_group))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after starting traffic for Quick "
                 "Flow Group '{q}'".format(t=wait_time, q=quick_flow_group))
        time.sleep(wait_time)

        # Verify Quick Flow Group state is now 'started'
        log.info("Verify Quick Flow Group '{}' state is now 'started'".\
                 format(quick_flow_group))
        try:
            assert 'started' == self.get_quick_flow_group_attribute(quick_flow_group=quick_flow_group, attribute='state')
        except AssertionError as e:
            raise GenieTgnError("Quick Flow Group '{}' state is not 'started'".\
                                format(quick_flow_group))
        else:
            log.info("Quick Flow Group '{}' state is 'started'".\
                     format(quick_flow_group))


    def stop_quick_flow_group(self, quick_flow_group, wait_time=15):
        '''Stop given Quick Flow Group on Ixia'''

        log.info(banner("Stopping traffic for Quick Flow Group '{}'".\
                        format(quick_flow_group)))

        # Find flow group object from flow group name
        qfg_obj = self.find_quick_flow_group_object(quick_flow_group=quick_flow_group)

        try:
            # Stop traffic for this Quick Flow Group
            self.ixNet.execute('stopStatelessTraffic', qfg_obj)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while stopping traffic for Quick Flow "
                                "Group '{}'".format(quick_flow_group))

        # Wait for user specified interval
        log.info("Waiting for '{t}' seconds after stopping traffic for Quick "
                 "Flow Group '{q}'".format(t=wait_time, q=quick_flow_group))
        time.sleep(wait_time)

        # Verify Quick Flow Group state is now 'stopped'
        log.info("Verify Quick Flow Group '{}' state is now 'stopped'".\
                 format(quick_flow_group))
        try:
            assert 'stopped' == self.get_quick_flow_group_attribute(quick_flow_group=quick_flow_group, attribute='state')
        except AssertionError as e:
            raise GenieTgnError("Quick Flow Group '{}' state is not 'stopped'".\
                                format(quick_flow_group))
        else:
            log.info("Quick Flow Group '{}' state is 'stopped'".\
                     format(quick_flow_group))


    #--------------------------------------------------------------------------#
    #                          Flow Statistics                                 #
    #--------------------------------------------------------------------------#

    def get_flow_statistics_data(self, traffic_stream, flow_data_field):
        '''Get value of flow_data_field of traffic_tream from "Flow Statistics" '''

        # Get all stream data for given traffic_stream
        try:
            return self.ixNet.execute('getValue',
                            '::ixNet::OBJ-/statistics/view:"Flow Statistics"',
                            traffic_stream, flow_data_field)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error while retrieving '{data}' for traffic "
                                "stream '{stream}' from 'Flow Statistics'".\
                                format(data=flow_data_field,
                                       stream=traffic_stream))


    #--------------------------------------------------------------------------#
    #                     Line / Packet / Layer2 bit rate                      #
    #--------------------------------------------------------------------------#

    def set_line_rate(self, traffic_stream, rate, flow_group='', stop_traffic_time=15, generate_traffic_time=15, apply_traffic_time=15, start_traffic_time=15):
        '''Set the line rate for given traffic stream or given flow group of a traffic stream'''

        # Verify rate value provided is <=100 as line rate is a percentage
        try:
            assert rate in range(100)
        except AssertionError as e:
            raise GenieTgnError("Invalid input rate={} provided. Line rate must"
                                " be between 0 to 100%".format(rate))

        # Get traffic item object from stream name
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

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
                config_elements = self.ixNet.getList(ti_obj, "configElement")
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
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

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
                config_elements = self.ixNet.getList(ti_obj, "configElement")
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
        ti_obj = self.find_traffic_stream_object(traffic_stream=traffic_stream)

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
                config_elements = self.ixNet.getList(ti_obj, "configElement")
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
