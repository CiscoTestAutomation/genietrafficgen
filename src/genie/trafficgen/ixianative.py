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
        self._genie_view = None
        self._genie_page = None
        self._golden_profile = prettytable.PrettyTable()

        # Get Ixia device arguments from testbed YAML file
        for key in ['ixnetwork_api_server_ip', 'ixnetwork_tcl_port', 'ixia_port_list',
                    'ixnetwork_version', 'ixia_chassis_ip', 'ixia_license_server_ip']:
            # Verify Ixia ports provided are a list
            if key is 'ixia_port_list':
                if not isinstance(self.connection_info[key], list):
                    log.error("Attribute 'ixia_port_list' is not a list as expected")
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
            log.info("Traffic is in 'stopped' state after applying traffic as"
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
            for statName in ["Tx Frame Rate", "Rx Frame Rate", "Loss %", "Frames Delta"]:
                stat = self._genie_view + '/statistic:' + '"{}"'.format(statName)
                if stat in availableStatList:
                    self.ixNet.setAttribute(stat, '-enabled', 'true')
                    self.ixNet.commit()

            # Create and set enumerationFilter to descending
            enumerationFilter = self.ixNet.add(self._genie_view+'/layer23TrafficFlowFilter', 'enumerationFilter')
            self.ixNet.setAttribute(enumerationFilter, '-sortDirection', 'descending')
            self.ixNet.commit()

            # Add 'Source/Dest Port Pair' column to TCL view (extracted through trackingFilterIds)
            source_dest_track_id = None
            trackingFilterIdList = self.ixNet.getList(self._genie_view, 'availableTrackingFilter')
            for track_id in trackingFilterIdList:
                if re.search('Source/Dest Port Pair', track_id):
                    source_dest_track_id = track_id
                    break
            if source_dest_track_id:
                self.ixNet.setAttribute(enumerationFilter, '-trackingFilterId', source_dest_track_id)
                self.ixNet.commit()

            # Re-enable TCL View "GENIE"
            self.ixNet.setAttribute(self._genie_view, '-enabled', 'true')
            self.ixNet.setAttribute(self._genie_view, '-visible', 'true')
            self.ixNet.commit()

            # Print to log
            log.info("Populated traffic statistics view 'GENIE' with required "
                     "data.")
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to populate traffic statistics view "
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


    def check_traffic_loss(self, loss_tolerance=15, check_interval=60, check_iteration=10):
        '''Check for traffic loss on a traffic stream configured on Ixia'''

        log.info(banner("Checking all streams for traffic loss on Ixia"))
        time.sleep(check_interval)

        for i in range(check_iteration):
            # Init
            loss_check_pass = True
            traffic_table = prettytable.PrettyTable()

            # Create table with traffic loss % and tx/rx frames count
            for field in ['Traffic Item', 'Frames Delta', 'Loss %', 'Tx Frames',
                          'Rx Frames']:
                try:
                    # Add traffic items from view 'Traffic Item Statistics'
                    traffic_table.add_column(field,self.ixNet.execute('getColumnValues',
                            '::ixNet::OBJ-/statistics/view:"Traffic Item Statistics"',
                            field))
                except Exception as e:
                    log.error(e)
                    raise GenieTgnError("Unable to get traffic statistics to "
                                        "check for traffic loss") from e

            # Print the table
            traffic_table.align = "l"
            log.info(traffic_table)

            # Check for traffic loss and tx/frames count for each traffic item
            for row in traffic_table:
                row.header = False ; row.border = False
                log.info("Traffic item '{}':".\
                        format(row.get_string(fields=["Traffic Item"]).strip()))

                # Check traffic loss
                if float(row.get_string(fields=["Loss %"]).strip()) <= float(loss_tolerance):
                    log.info("  * Traffic loss of {l}% is within expected loss "
                            "tolerance of {t}%".format(t=loss_tolerance,
                            l=row.get_string(fields=["Loss %"]).strip()))
                else:
                    loss_check_pass = False
                    log.error("  * Traffic loss of {l}% is *not* within expected"
                            " loss tolerance of {t}%".format(t=loss_tolerance,
                            l=row.get_string(fields=["Loss %"]).strip()))

            # If all streams had no traffic loss/frames loss, break
            if loss_check_pass:
                log.info("Verified all traffic streams for traffic loss")
                break
            elif i == check_iteration-1:
                raise GenieTgnError("Traffic loss observed and streams have not"
                                    " converged to steady state")
            else:
                log.error("Sleeping '{}' seconds and rechecking traffic streams".\
                            format(check_interval))
                time.sleep(check_interval)


    def create_traffic_profile(self, set_golden=False, clear_stats_time=30,
                               view_create_interval=30, view_create_iteration=5):
        '''Create traffic profile of configured streams on Ixia'''

        # If Genie view and page has not been created before, create one
        if not self._genie_view or not self._genie_page:
            self.create_genie_statistics_view(view_create_interval=view_create_interval,
                                              view_create_iteration=view_create_iteration)

        # Clear stats and wait
        self.clear_statistics(wait_time=clear_stats_time)

        # Parse traffic statistics view 'GENIE' for traffic profile data
        log.info(banner("Creating traffic profile of configured streams on Ixia"))
        profile_table = prettytable.PrettyTable()
        try:
            # Set the profile table headers
            headers = self.ixNet.getAttribute(self._genie_page, '-columnCaptions')
            del headers[0]
            headers[1], headers[0] = headers[0], headers[1]
            profile_table.field_names = headers

            # Add rows with data
            for item in self.ixNet.getAttribute(self._genie_page, '-rowValues'):
                # Edit list as required for profile table
                row_item = item[0]
                del row_item[0]
                row_item[0], row_item[1] = row_item[1], row_item[0]
                profile_table.add_row(row_item)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to create traffic profile of all "
                                "configured streams") from e
        else:
            log.info("Created traffic streams snapshot profile of all configured"
                     "streams on Ixia")

        # Align and print profile table in the logs
        profile_table.align = "l"
        log.info(profile_table)

        # If flag set, reset the golden profile
        if set_golden:
            log.info("\nSet golden traffic profile\n")
            self._golden_profile = profile_table

        # Return profile table to caller
        return profile_table


    def compare_traffic_profile(self, profile1, profile2, loss_tolerance=1,
                                frames_tolerance=2, rate_tolerance=2):
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
        compare_profile = True
        names = ['src_dest_pair', 'stream_name', 'frames_delta', 'loss', 'tx_rate', 'rx_rate']
        for profile1_row, profile2_row in zip(profile1, profile2):
            profile1_row.header = False ; profile2_row.header = False
            profile1_row_values = {} ; profile2_row_values = {}
            for item, name in zip(profile1_row._rows[0], names):
                profile1_row_values[name] = item
            for item, name in zip(profile2_row._rows[0], names):
                profile2_row_values[name] = item

            # Ensure profiles have traffic data/content
            if profile1_row_values and profile2_row_values:
                try:
                    assert profile1_row_values['src_dest_pair'] == profile2_row_values['src_dest_pair']
                    assert profile1_row_values['stream_name'] == profile2_row_values['stream_name']
                    assert abs(int(profile1_row_values['frames_delta']) - int(profile2_row_values['frames_delta'])) <= int(frames_tolerance)
                    assert abs(float(profile1_row_values['loss']) - float(profile2_row_values['loss'])) <= float(loss_tolerance)
                    assert abs(float(profile1_row_values['tx_rate']) - float(profile2_row_values['tx_rate'])) <= float(rate_tolerance)
                    assert abs(float(profile1_row_values['rx_rate']) - float(profile2_row_values['rx_rate'])) <= float(rate_tolerance)
                except AssertionError as e:
                    log.error("Profile1:\n{}".format(profile1_row))
                    log.error("Profile2:\n{}".format(profile2_row))
                    raise GenieTgnError("Comparison failed for traffic item: "
                                        "'{t}' '{s}'".format(
                                        t=profile1_row_values['stream_name'],
                                        s=profile1_row_values['src_dest_pair'])) from e
                else:
                    log.info("Comparison passed for traffic item: '{t}' '{s}'".\
                            format(t=profile1_row_values['stream_name'],
                            s=profile1_row_values['src_dest_pair']))
            else:
                raise GenieTgnError("Profiles provided do not have traffic data")
