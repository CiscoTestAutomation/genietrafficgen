'''
Connection Implementation class for Spirent traffic generator using
stcrestclient Python package to interact with Spirent device:
https://pypi.org/project/stcrestclient/


'''

# Python
import re
import os
import time
import logging
import json
import requests
from prettytable import PrettyTable

# pyATS
from pyats.log.utils import banner
from pyats.connections import BaseConnection
from pyats.utils.secret_strings import SecretString, to_plaintext

# Genie
from genie.utils.summary import Summary
from genie.harness.utils import get_url
from genie.trafficgen.trafficgen import TrafficGen
from genie.harness.exceptions import GenieTgnError

try:
    from stcrestclient import stchttp
except ImportError as e:
    raise ImportError("Spirent package is not installed in virtual env - "
                      "https://pypi.org/project/stcrestclient/") from e

# Logger
log = logging.getLogger(__name__)

GENIE_VIEW_NAME="GENIE"

# helper function
def cast_number(value):
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value

# Split result data of spirent
def split_string(s):
    pattern = r'\{([^}]*)\}|\S+'
    return [m.group(1) if m.group(1) else m.group(0) for m in re.finditer(pattern, s)]

class Spirent(TrafficGen):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.device = self.device or kwargs.get('device')
        self.via = kwargs.get('via', 'tgn')

        if self.device is not None:
            connection_args = self.device.connections.get(self.via)
        else:
            connection_args = kwargs

        creds = self.device.credentials
        self.username = creds.get('default', {}).get('username', 'admin')
        self.password = creds.get('default', {}).get('password', 'spirent')
        if isinstance(self.password, SecretString):
            self.password = to_plaintext(self.password)

        self.ls_addr = str(connection_args.get('server_ip', ''))
        self.ls_port = connection_args.get('server_port', '80')
        self.user_name = connection_args.get('user_name')
        self.session_name = connection_args.get('session_name')
        self.session_id = ' - '.join((self.session_name, self.user_name))
        self.chassis = connection_args.get('chassis')
        self.chassis_list = []
        if self.chassis:
            for one in self.chassis:
                chassis_ip = one.get('ip')
                chassis_ports = one.get('port_list')
                if isinstance(chassis_ports,list):
                    self.chassis_list += [ '//{}/{}'.format(chassis_ip, p)  for p in chassis_ports ]
                else:
                    self.chassis_list.append('//{}/{}'.format(chassis_ip, chassis_ports))
        # Get results from IQ
        self.use_iq = connection_args.get('use_iq', False)

        self.golden_profile = None
        self.drv_result = None
        self.drv = None
        self.stream_dataset = None

        # Init class variables
        self._is_connected = False

        # Spirent Chassis Details
        header = "Spirent Configuration Details"
        summary = Summary(title=header, width=80)
        summary.add_message(msg='Spirent API Server: {}:{}'.format(self.ls_addr, self.ls_port))
        summary.add_sep_line()
        summary.add_message(msg='Spirent Session: {}'.format(self.session_id))
        summary.add_sep_line()
        if len(self.chassis_list) > 0:
            summary.add_message(msg='Spirent Chassis: {}'.format(self.chassis_list))
            summary.add_sep_line()
        summary.print()

        # Genie Traffic Documentation
        url = get_url().replace("genie", "genietrafficgen")
        log.info('For more information, see Genie traffic documentation: \n'
                 '  {}spirent.html'.format(url))

    def isconnected(func):
        '''Decorator to make sure session to device is active

           There is limitation on the amount of time the session can be active
           to Spirent API server. However, there are no way to verify if the
           session is still active unless we test sending a command.
         '''
        def decorated(self, *args, **kwargs):
            # Check if connected
            try:
                log.propagate = False
                self.stc.system_info()
            except Exception:
                self.connect()
            finally:
                log.propagate = True
            return func(self, *args, **kwargs)
        return decorated

    @BaseConnection.locked
    def connect(self):
        '''Connect to Spirent'''
        log.info(banner("Connecting to Spirent"))
        try:
            self.stc = stchttp.StcHttp(self.ls_addr, self.ls_port)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to connect to device '{}' on '{}':'{}' ".format(
                self.device.name, self.ls_addr, self.ls_port)) from e

        try:
            sessions_list = self.stc.sessions()
            if self.session_id in sessions_list:
                self.stc.join_session(self.session_id)
                log.info("Connected to existing session:{}".format(self.session_id))
            else:
                self.stc.new_session(self.user_name, self.session_name, kill_existing=False)
                log.info("Created new session:{}".format(self.session_id))

        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to create sessions {} - {}".format(self.session_name, self.user_name)) from e
        else:
            self._is_connected = True
            log.info("Connected to Spirent API server '{}:{}'".format(self.ls_addr, self.ls_port))
        

    @BaseConnection.locked
    def disconnect(self):
        '''Disconnect from traffic generator device'''
        log.info(banner("Disconnecting to Spirent"))
        try:
            ports = self.stc.get('Project1', 'children-port')
            ports_list = [] if len(ports) == 0 else ports.split(' ')
            self.stc.perform("DetachPortsCommand", PortList=ports_list)
            
            self.stc.end_session(True, sid=self.session_id)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to disconnect from '{}".\
                                format(self.device.name))
        else:
            self._is_connected = False
            log.info("Disconnected from Spirent API server '{}:{}'".\
                     format(self.ls_addr, self.ls_port))
    
    @BaseConnection.locked
    @isconnected
    def load_configuration(self, configuration, wait_time=60):
        '''Load static configuration file onto Spirent'''

        log.info(banner("Loading configuration"))

        # Spirent Configuration Details
        header = "Spirent Configuration Information"
        summary = Summary(title=header, width=80)
        summary.add_message(msg='File: {}'.format(configuration))
        summary.add_sep_line()
        summary.print()

        # Execute load config on Spirent
        try:
            self.stc.upload(configuration)
            # Load the config.
            self.stc.perform('LoadFromXml', filename=os.path.basename(configuration))

        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to load configuration file '{f}' onto "
                                "device '{d}'".format(f=configuration, d=self.device.name)) from e
        else:
            log.info("Loaded configuration file '{f}' onto device '{d}'".\
                    format(f=configuration, d=self.device.name))

        # Wait after loading configuration file
        log.info("Waiting for '{}' seconds after loading configuration...".format(wait_time))
        time.sleep(wait_time)

        try:
            ports = self.stc.get('Project1', 'children-port')
            ports_list = [] if len(ports) == 0 else ports.split(' ')
            if len(ports_list) != 0 and len(self.chassis_list) == len(ports_list):
                for i in range(len(ports_list)):
                    self.stc.config(ports_list[i], location=self.chassis_list[i])
            
            self.stc.perform("AttachPortsCommand", autoconnect=True, RevokeOwner=True)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to relocate ports or bring ports online on device '{}'".format(self.device.name)) from e
        
    @BaseConnection.locked
    @isconnected
    def save_configuration(self, config_file):
        '''Saving existing configuration on Spirent into a file'''

        log.info(banner("Saving configuration..."))
        file_name = os.path.basename(config_file)

        # Save existing config on Spirent
        try:
            self.stc.perform('SaveAsXml', filename=file_name)
            self.stc.download(file_name, save_as=config_file)

        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to save configuration from device '{}' "
                                "to file '{}'".format(self.device.name,
                                config_file)) from e
        else:
            log.info("Saved configuration from device '{}' to file '{}'".\
                    format(self.device.name, config_file))

    @BaseConnection.locked
    @isconnected
    def remove_configuration(self, wait_time=30):
        # Spirent does not support remove_configuration
        # Add this method to work around the issue if --tgn-remove-configuration is set to True.
        log.info(banner("Removing configuration..."))
        
        # Wait after removing configuration file
        log.info("Waiting for '{}' seconds after removing configuration...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def start_all_protocols(self, wait_time=60):
        '''Start all protocols on Spirent'''
        log.info(banner("Starting routing engine"))

        # Start All protocols on Spirent
        try:
            devicesstartallstatus = self.stc.perform('DevicesStartAllCommand', Project='Project1')
            log.info("start_all_protocols: {}".format(devicesstartallstatus))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start all protocols on device '{}'".format(self.device.name)) from e

        log.info("Started protocols on device '{}'".format(self.device.name))

        # Wait after starting protocols
        log.info("Waiting for '{}' seconds after starting all protocols...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def stop_all_protocols(self, wait_time=60):
        '''Stop all protocols on Spirent'''
        log.info(banner("Stopping routing engine"))

        # Stop protocols on Spirent
        try:
            devicesstopallstatus = self.stc.perform('DevicesStopAllCommand', Project='Project1')
            log.info("stop_all_protocols: {}".format(devicesstopallstatus))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop all protocols on device '{}'".format(self.device.name)) from e
        
        log.info("Stopped protocols on device '{}'".format(self.device.name))

        # Wait after stopping protocols
        log.info("Waiting for  '{}' seconds after stopping all protocols...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def apply_traffic(self, wait_time=60):
        '''Apply L2/L3 traffic on Spirent'''
        log.info(banner("Applying L2/L3 traffic"))

        # Apply traffic on Spirent
        try:
            self.stc.apply()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to apply L2/L3 traffic on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Applied L2/L3 traffic on device '{}'".format(self.device.name))

        # Wait after applying L2/L3 traffic
        log.info("Waiting for '{}' seconds after applying L2/L3 traffic...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def send_arp(self, wait_time=10):
        '''Send ARP to all interfaces from Spirent'''
        log.info(banner("Sending ARP to all interfaces from Spirent"))

        # Send ARP from Spirent
        try:
            arpstatus = self.stc.perform('ArpNdStartCommand', WaitForArpToFinish="TRUE", HandleList='Project1')
            log.info("send_arp: {}".format(arpstatus))
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to send ARP to all interfaces on device"
                                " '{}'".format(self.device.name)) from e
        # Verify return
        #try:
        #    assert arpstatus['ArpNdState'] == 'SUCCESSFUL'
        #except AssertionError as e:
        #    log.error(arpstatus['ArpNdState'])
        #    raise GenieTgnError("Unable to send ARP to all interfaces on device '{}'".format(self.device.name)) from e
        #else:
        log.info("Sent ARP to all interfaces on device '{}'".format(self.device.name))

        # Wait after sending ARP
        log.info("Waiting for '{}' seconds after sending ARP to all interfaces...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def send_ns(self, wait_time=10):
        '''Send NS to all interfaces from Spirent'''
        log.info(banner("Sending NS to all interfaces from Spirent"))

    @BaseConnection.locked
    @isconnected
    def start_traffic(self, wait_time=60):
        '''Start traffic on Spirent'''
        log.info(banner("Starting L2/L3 traffic"))

        # Start traffic on Spirent
        try:
            self.stc.perform('GeneratorStartCommand')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to start traffic on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Startted L2/L3 traffic on device '{}'".format(self.device.name))

        # Wait after starting L2/L3 traffic for streams to converge to steady state
        log.info("Waiting for '{}' seconds after starting L2/L3 traffic "
                 "for streams to converge to steady state...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def stop_traffic(self, wait_time=60, max_time=180):
        '''Stop traffic on Spirent'''
        log.info(banner("Stopping L2/L3 traffic"))

        # Stop traffic on Spirent
        try:
            self.stc.perform('GeneratorStopCommand')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to stop traffic on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Stopped L2/L3 traffic on device '{}'".format(self.device.name))

        # Wait after stopping L2/L3 traffic for streams
        log.info("Waiting for '{}' seconds after stopping L2/L3 traffic".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def clear_statistics(self, wait_time=10):
        '''Clear all traffic, port, protocol statistics on traffic generator device'''
        log.info(banner("Clear all traffic, port, protocol statistics"))

        # Clear traffic on Spirent
        try:
            self.stc.perform('ResultsClearAllCommand')
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to clear traffic statistics on device '{}'".\
                                format(self.device.name)) from e
        else:
            log.info("Successfully cleared traffic statistics on device '{}'".format(self.device.name))

    @BaseConnection.locked
    @isconnected
    def create_genie_statistics_view(self, view_create_interval=30, view_create_iteration=10, disable_tracking=False, disable_port_pair=False):
        '''Creates a custom View named "Genie" with the required stats data'''
        log.info(banner("Creating new custom Spirent traffic statistics view '{}'".format(GENIE_VIEW_NAME)))
        if self.use_iq:
            self.create_genie_iq_view()
        else:
            self.create_genie_dynamic_view()


    @BaseConnection.locked
    @isconnected
    def check_traffic_loss(self, traffic_streams=None, max_outage=120,
                           loss_tolerance=15, rate_tolerance=5,
                           check_iteration=10, check_interval=60,
                           outage_dict=None, clear_stats=False,
                           clear_stats_time=30, pre_check_wait=None,
                           disable_tracking=False, disable_port_pair=False,
                           raise_on_loss=True, check_traffic_type=False,
                           **kwargs):
        '''Check for traffic loss on a traffic stream configured on traffic generator device'''
        log.info(banner("Check for traffic loss on a traffic stream"))

        traffic_data_set = []

        for i in range(check_iteration):
            # Init
            overall_result = {}

            # Get and display 'GENIE' traffic statistics table containing outage/loss values
            traffic_table = self.create_traffic_streams_table(
                                    clear_stats=clear_stats,
                                    clear_stats_time=clear_stats_time,
                                    disable_tracking=disable_tracking,
                                    disable_port_pair=disable_port_pair)

            if not traffic_table._rows:
                raise GenieTgnError('No trafic data found')

            traffic_data = {
                "stream": {row[0]: dict(zip(traffic_table.field_names, [cast_number(v) for v in row])) for row in traffic_table._rows}
            }
            traffic_data_set.append(traffic_data)

            # Log iteration attempt to user
            log.info("\nAttempt #{}: Checking for traffic outage/loss".format(i+1))


            # Check all streams for traffic outage/loss
            for row in traffic_table:

                # Strip headers and borders
                row.header = False ; row.border = False

                # Get data
                try:
                    stream = row.get_string(fields=["Traffic Item"]).strip()
                except Exception as e:
                    raise GenieTgnError("Traffic Item doesn't exist in GENIE view. Make sure to configure more than 1 traffic item, user defined stats/custom statistics view with a single traffic is not supported.: {}".format(e))

                if not disable_port_pair:
                    src_dest_pair = row.get_string(fields=["Source/Dest Port Pair"]).strip()
                else:
                    src_dest_pair = None
 
                # --------------
                # BEGIN CHECKING
                # --------------
                log.info(banner("Checking traffic stream: '{s} | {t}'".format(s=src_dest_pair, t=stream)))

                # 1- Verify traffic Outage (in seconds) is less than tolerance threshold
                log.info("1. Verify traffic outage (in seconds) is less than "
                         "tolerance threshold of '{}' seconds".format(max_outage))
                # Check that 'Outage (seconds)' is not '' or '*'
                current_outage = row.get_string(fields=["Outage (seconds)"]).strip()
                
                if float(current_outage) <= float(max_outage):
                    log.info("* Traffic outage of '{c}' seconds is within "
                             "expected maximum outage threshold of '{g}' seconds".\
                             format(c=current_outage, g=max_outage))
                    outage_check = True
                else:
                    outage_check = False
                    log.error("* Traffic outage of '{c}' seconds is *NOT* within "
                              "expected maximum outage threshold of '{g}' seconds".\
                              format(c=current_outage, g=max_outage))
                print("outage:", current_outage, max_outage, outage_check)

                # 2- Verify current loss % is less than tolerance threshold
                log.info("2. Verify current loss % is less than tolerance "
                         "threshold of '{}' %".format(loss_tolerance))
                # Check that 'Loss %' is not '' or '*'
                current_loss_percentage = row.get_string(fields=["Loss %"]).strip()
                # Now compare
                if float(current_loss_percentage) <= float(loss_tolerance):
                    log.info("* Current traffic loss of {l}% is within"
                             " maximum expected loss tolerance of {g}%".\
                             format(l=current_loss_percentage, g=loss_tolerance))
                    loss_check = True
                else:
                    loss_check = False
                    log.error("* Current traffic loss of {l}% is *NOT* within"
                              " maximum expected loss tolerance of {g}%".\
                              format(l=current_loss_percentage, g=loss_tolerance))
                print("loss_percentage:", current_loss_percentage, loss_tolerance, loss_check)
                '''
                # 3- Verify difference between Tx Rate & Rx Rate is less than tolerance threshold
                log.info("3. Verify difference between Tx Rate & Rx Rate is less "
                         "than tolerance threshold of '{}' pps".format(rate_tolerance))
                # Get 'Tx Frame Rate'
                tx_rate = row.get_string(fields=["Tx Frame Rate"]).strip()
                
                # Get 'Rx Frame Rate'
                rx_rate = row.get_string(fields=["Rx Frame Rate"]).strip()
                
                # Now compare
                if abs(float(tx_rate) - float(rx_rate)) <= float(rate_tolerance):
                    log.info("* Difference between Tx Rate '{t}' and Rx Rate"
                             " '{r}' is within expected maximum rate loss"
                             " threshold of '{g}' packets per second".\
                             format(t=tx_rate, r=rx_rate, g=rate_tolerance))
                    rate_check = True
                else:
                    rate_check = False
                    log.error("* Difference between Tx Rate '{t}' and Rx Rate"
                              " '{r}' is *NOT* within expected maximum rate loss"
                              " threshold of '{g}' packets per second".\
                              format(t=tx_rate, r=rx_rate, g=rate_tolerance))
                print("rate_check:", abs(float(tx_rate) - float(rx_rate)), rate_tolerance, rate_check)
                '''
                # Set overall result
                if outage_check and loss_check:
                    continue
                else:
                    overall_result.setdefault('streams', {})['{s} | {t}'.\
                                   format(s=src_dest_pair, t=stream)] =\
                                   "FAIL"

            # Check if iteration required based on results
            if 'streams' not in overall_result:
                log.info("\nSuccessfully verified traffic outages/loss is within "
                         "tolerance for given traffic streams")
                break
            elif i == check_iteration or i == check_iteration-1:
                # End of iterations, raise Exception and exit
                if raise_on_loss:
                    raise GenieTgnError("Unexpected traffic outage/loss is observed")
            else:
                # Traffic loss observed, sleep and recheck
                log.error("\nTraffic loss/outage observed for streams:")
                for item in overall_result['streams']:
                    log.error("* {}".format(item))
                log.error("Sleeping '{s}' seconds and rechecking streams for "
                          "traffic outage/loss".format(s=check_interval))
                time.sleep(check_interval)

        return traffic_data_set


    @BaseConnection.locked
    @isconnected
    def create_traffic_profile(self):
        '''Create traffic profile of configured streams on traffic generator device'''
        log.info(banner("Create traffic profile of configured streams"))


    @BaseConnection.locked
    @isconnected
    def compare_traffic_profile(self, profile1, profile2, loss_tolerance=5, rate_tolerance=2):
        '''Compare two traffic generator device traffic profiles'''
        log.info(banner("Compare traffic profiles"))


    @BaseConnection.locked
    @isconnected
    def create_traffic_streams_table(self, set_golden=False, clear_stats=False,
        clear_stats_time=30, view_create_interval=30, view_create_iteration=5,
        disable_tracking=False, disable_port_pair=False):
        '''Returns traffic profile of configured streams on Spirent'''
        log.info(banner("Create traffic stream table"))

        # Clear stats and wait
        if clear_stats:
            self.clear_statistics(wait_time=clear_stats_time)

        if self.use_iq:
            traffic_table = self.create_tciq_traffic_streams_table()
        else:
            traffic_table = self.create_drv_traffic_streams_table()
        

        traffic_table.align = "l"
        log.info(traffic_table)

        # If flag set, reset the golden profile
        if set_golden:
            log.info("\nSetting golden traffic profile\n")
            self.golden_profile = traffic_table
        
        return traffic_table

    #--------------------------------------------------------------------------#
    #                                  Utils                                   #
    #--------------------------------------------------------------------------#

    @BaseConnection.locked
    @isconnected
    def get_data_from_testcenter_iq(self):
        '''Query Data from TestCenter IQ'''
        # Query json can define the format of data from TestCenter IQ
        
        json_file = os.path.join(os.path.dirname(__file__), "iq_files", "streamblock.json")
        try:
            with open(json_file, 'r') as file:
                queryjson = json.load(file)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to load file {} on device '{}'".format(json_file, self.device.name)) from e

        rows = {}
        try:
            log.info("Get query url based on TestCenter database id...")
            test_info = self.stc.get('project1', 'children-TestInfo')
            self.stc.config(test_info, testName='GENIE', active=True, LocalActive=True)
            db_id = self.stc.get(test_info, 'resultdbid')
            temeva_results_config = self.stc.get('system1', 'children-temevaresultsconfig')
            serviceUrl = self.stc.get(temeva_results_config, 'ServiceUrl')
            post_url = serviceUrl + '/queries'
            post_data = {
                "database": {
                "id": db_id
                },
                "mode": "once",
                "definition": queryjson
            }
            post_headers = {'Content-Type': 'application/json'}
            post_result = requests.post(url=post_url, json=post_data, headers=post_headers, timeout=20).json()
            result = post_result.get('result')
            
            if result is not None:
                rows = result.get('rows')
            else:
                raise GenieTgnError("No data found from TestCenter IQ on device '{}'".format(self.device.name)) from e
            
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to query data from TestCenter IQ on device '{}'".format(self.device.name)) from e

        return rows

    @BaseConnection.locked
    @isconnected
    def create_genie_dynamic_view(self):
        '''Create Spirent Dynamic View'''

        if self.drv == None or self.drv_result == None:
            ret = self.get_drv_genie_view()
            if ret:
                log.info("Succeed to get Spirent Dynamic View:{}".format(GENIE_VIEW_NAME))
                return
        else:
            log.info("Spirent Dynamic View {} has been created, exit!".format(GENIE_VIEW_NAME))
            return
            
        log.info("Create Spirent Dynamic View")

        select_properties = ['StreamBlock.Name', 'Port.Name', 
                             'StreamBlock.TxFrameCount', 'StreamBlock.RxSigFrameCount',
                             'StreamBlock.DroppedFrameCount', 'StreamBlock.DroppedFramePercent', 
                             'StreamBlock.TxFrameRate', 'StreamBlock.RxSigFrameRate']
        lst_ports = []
        try:
            ports = self.stc.get('Project1', 'children-port')
            lst_ports = ports.split(' ')
            assert len(lst_ports) > 0

        except AssertionError as e:
            log.error("No Ports founds!")
            raise GenieTgnError("No ports found on device '{}'".format(self.device.name)) from e

        try:
            streamblockrdsA = self.stc.perform('ResultsSubscribeCommand',
                                Parent='project1',
                                ConfigType="Streamblock",
                                ResultType="TxStreamBlockResults",
                                RecordsPerPage=256)

            stream_dataset = streamblockrdsA['ReturnedResultDataSet']
            self.stc.create("ResultQuery", under=stream_dataset,
                                                ResultRootList='project1',
                                                ConfigClassId="StreamBlock",
                                                ResultClassId="RxStreamBlockResults")

            # subscribe to rxstreamsummaryresults
            rx_stream_summary_results = self.stc.perform('ResultsSubscribeCommand',
                                                        Parent='project1',
                                                        ConfigType='Streamblock',
                                                        ResultType='RxStreamSummaryResults',
                                                        RecordsPerPage=256)

            # subscribe to TxStreamResults
            tx_stream_results = self.stc.perform('ResultsSubscribeCommand',
                                                    Parent='project1',
                                                    ConfigType='Streamblock',
                                                    ResultType='TxStreamResults',
                                                    RecordsPerPage='256')

            self.drv = self.stc.create('DynamicResultView', under='project1', name=GENIE_VIEW_NAME)
            self.drv_result = self.stc.create('PresentationResultQuery', under=self.drv, name=GENIE_VIEW_NAME)
            log.info("Create Dynamic view with DRV:{}, DRV Result:{}".format(self.drv, self.drv_result))

            self.stc.config(self.drv_result, SelectProperties=select_properties, FromObjects=lst_ports, LimitOffset=0, LimitSize=4000)
            self.stc.perform('SubscribeDynamicResultViewCommand', DynamicResultView=self.drv)
            self.stc.apply()

            self.stc.perform("RefreshResultView", ResultDataSet=stream_dataset)
            self.stc.perform("UpdateDynamicResultViewCommand", DynamicResultView=self.drv)

        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to Create Genie Statistics View on device '{}'".format(self.device.name)) from e

    @BaseConnection.locked
    @isconnected
    def create_genie_iq_view(self):
        '''Create Genie View of TestCenter IQ'''
        log.info("Create Genie View of TestCenter IQ")

        try:
            # get all port list for generator start
            genie_view = "stream_block_name tx_port_name rx_port_name tx_stream_stats_frame_count " + \
                        "rx_stream_stats_frame_count tx_stream_stats_frame_rate rx_stream_stats_frame_rate " + \
                        "stream_stats_frame_loss_percent"
            selector_profile = self.stc.get('system1', "children-spirent.results.EnhancedResultsSelectorProfile")
            groupfilter = self.stc.create('spirent.results.EnhancedResultsGroupFilter', under=selector_profile, LiveFacts=genie_view)
            self.stc.config(groupfilter, name="GEINIE", RefreshInterval=1000)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to Create Genie View of TestCenter IQ on device '{}'".format(self.device.name)) from e

    @BaseConnection.locked
    @isconnected
    def create_drv_traffic_streams_table(self):
        '''Create Traffic Stream Table of DRV type'''
        log.info("Create Traffic Stream Table of DRV type")

        # Init
        traffic_table = PrettyTable()

        if self.drv == None or self.drv_result == None:
            self.create_genie_statistics_view()

        try:
            #self.stc.perform("RefreshResultView", ResultDataSet=self.stream_dataset)
            self.stc.perform("UpdateDynamicResultViewCommand", DynamicResultView=self.drv)
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to Refresh Genie result view on device '{}'".format(self.device.name)) from e

        traffic_table.field_names = ["Source/Dest Port Pair", "Traffic Item",
                                    "Tx Frames", "Rx Frames", 
                                    "Frames Delta", "Loss %",
                                    "Tx Frame Rate", "Rx Frame Rate", "Outage (seconds)"]

        result_view_data_list = []
        try:
            #properties = stc.get(self.drv_result, 'SelectProperties')
            result_view_data_list = self.stc.get(self.drv_result, 'children-ResultViewData').split()
            assert len(result_view_data_list) > 0
        except AssertionError as e:
            log.error("No result data founds!")
            raise GenieTgnError("No result data on device '{}'".format(self.device.name)) from e

        streams_info = {}
        try:
            result = self.stc.perform("GetObjectsCommand", ClassName="StreamBlock", PropertyList="Name parent.name children-rxstreamblockresults")
            my_dict = json.loads(result['PropertyValues'])
            for key in  my_dict:
                rxport = self.stc.get(my_dict[key]['children-rxstreamblockresults'].split()[0]+'?RxPort')
                rxport = "Unknown" if rxport=="" else rxport
                streams_info[my_dict[key]['Name']] = rxport.split()[0]
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to Get RX port information on device '{}'".format(self.device.name)) from e

        try:
            for result_view_data in result_view_data_list:
                data_list = []
                result_data = self.stc.get(result_view_data, 'ResultData')
                raw_data = split_string(result_data)
                if len(raw_data) != 10:
                    log.warning("Skip invalid data {}".format(raw_data))
                    continue

                del raw_data[-2:]
                
                stream_name = raw_data[0]

                data_list.append(raw_data[1].split()[0]+'-'+streams_info[stream_name])
                data_list.append(stream_name)
                
                #Calculate outage
                try:
                    # Frames Delta/Tx Frame Rate
                    outage = round(float(raw_data[4])/float(raw_data[6]), 3)
                except ZeroDivisionError:
                    outage = 0.0
                raw_data.append(str(outage))
                data_list += raw_data[2:]
                traffic_table.add_row(data_list)

        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to Get Genie Statistics on device '{}'".format(self.device.name)) from e
        
        return traffic_table

    @BaseConnection.locked
    @isconnected
    def create_tciq_traffic_streams_table(self):
        '''Create Traffic Stream Table of TCIQ type'''
        log.info("Create Traffic Stream Table of TCIQ type")

        # Init
        traffic_table = PrettyTable()

        try:
            selector_profile = self.stc.get('system1', "children-spirent.results.EnhancedResultsSelectorProfile")
            groupfilter_list = self.stc.get(selector_profile, "children-spirent.results.EnhancedResultsGroupFilter").split(" ")
            exist_genie_view = False
            for group_filter in groupfilter_list:
                filter_name = self.stc.get(group_filter, 'name')
                if "GENIE" == filter_name:
                    exist_genie_view == True

            log.info("Create selector profile to query data from TestCenter IQ.")
            if not exist_genie_view:
                self.create_genie_iq_view()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to create group filter on device '{}'".format(self.device.name)) from e

        try:
            all_rows = self.get_data_from_testcenter_iq()
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to get data from Testcenter IQ on device '{}'".format(self.device.name)) from e

        traffic_table.field_names = ["Source/Dest Port Pair", "Traffic Item", 
                                     "Tx Frames", "Rx Frames", "Frames Delta", 
                                     "Tx Frame Rate", "Rx Frame Rate",
                                     "Loss %", "Outage (seconds)"]

        # split row values and fill the table with splitted data 
        if len(all_rows[0]) < 8:
            raise GenieTgnError("Incorrect Data from TestCenter IQ on device '{}'".format(self.device.name)) from e

        for row in all_rows:
            # get port pair value
            row_item = [row[1] + "-" + row[2]]
            # get traffic name for traffic item column
            row_item.append(row[0])
            # get Tx Frames and Rx Frames
            row_item+= row[3:5]
            # calcuate frames delta 
            frames_delta = int(row[3]) - int(row[4])
            row_item.append(frames_delta)
            # get tx/rx frames rate
            row_item+= row[5:7]
            # get frame loss percent
            row_item.append(round(float(row[7]),2))
            # get tx frame rate
            tx_frame_rate = row[5]
            try:
                outage_seconds = round(float(frames_delta)/float(tx_frame_rate), 3)
            except ZeroDivisionError:
                outage_seconds = 0.0
            except Exception as e:
                log.error(e)
                raise GenieTgnError("Unable to calcuate outage seconds on device '{}'".format(self.device.name)) from e

            # add outage seconds into a row data 
            row_item.append(str(outage_seconds))
            # add a row data into the traffic table
            traffic_table.add_row(row_item)
        
        return traffic_table

    @BaseConnection.locked
    @isconnected
    def get_drv_genie_view(self):
        '''Get the handle of DRV name'''
        log.info(banner("Trying to get dynamic view of {}".format(GENIE_VIEW_NAME)))
        try:
            result = self.stc.perform("GetObjectsCommand", ClassName="DynamicResultView", PropertyList="Name children", Condition="Name='{}'".format(GENIE_VIEW_NAME))
            my_dict = json.loads(result['PropertyValues'])

            assert len(my_dict) >= 1
            for key in  my_dict:
                self.drv = key
                self.drv_result = my_dict[key]['children'].split()[0]
                log.info("Get the handle of DRV:{}, DRV Result:{}".format(self.drv, self.drv_result))
                break

        except AssertionError as e:
            log.info("No DynamicResultView with name {} found!".format(GENIE_VIEW_NAME))
            return False

        except Exception as e:
            log.error(e)
            raise GenieTgnError("Unable to Get DynamicResultView on device '{}'".format(self.device.name)) from e
        
        return True
