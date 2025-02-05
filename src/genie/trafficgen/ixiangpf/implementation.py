"""
Connection Implementation class for Ixia Traffic Generator using
NGPF APIs
https://github.com/OpenIxia/IxNetwork/tree/master/HighLevelApi/Ngpf/Python

Requirements:
    * IxOS/IxVM 7.50 or higher
    * IxNetwork EA version 7.50 or higher
"""

# Python
import re
import os
import sys
import csv
import time
import logging
from shutil import copyfile
from functools import wraps
from prettytable import PrettyTable, from_csv

# pyATS
from pyats.easypy import runtime
from pyats.log.utils import banner
from pyats.connections import BaseConnection
from pyats.utils.secret_strings import SecretString, to_plaintext
from pyats.connections.utils import set_hltapi_environment_variables

# Genie
from genie.utils.timeout import Timeout
from genie.utils.summary import Summary
from genie.harness.utils import get_url
from genie.trafficgen.trafficgen import TrafficGen

# inherit IxiaNative
from genie.trafficgen.ixianative import IxiaNative
from genie.harness.exceptions import GenieTgnError

# IxNetwork Native
try:
    from IxNetwork import IxNet, IxNetError
except ImportError as e:
    raise ImportError(
        "IxNetwork package is not installed in virtual env - "
        "https://pypi.org/project/IxNetwork/"
    ) from e


# helper function
def cast_number(value):
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


# Logger
log = logging.getLogger(__name__)

# ixNet pass
_PASS = "::ixNet::OK"


# Inherit from IxiaNative so that we can continue using IxiaNative low level Python methods
class IxiaNgpf(IxiaNative):
    """ """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        log.info("Detecting IxNetwork version")
        log.info(self.ixnetwork_version)
        # Set environment variables for IXIA NGPF connection
        # This is crucial as we need the right HLTAPI libraries loaded correctly as per the version
        ixia_env = set_hltapi_environment_variables(self.ixnetwork_version)
        # Ixia NGPF
        try:
            from ixiatcl import IxiaTcl
            from ixiahlt import IxiaHlt
            from ixiangpf import (
                IxiaNgpf as IxiaNgpfft,
            )  # rename since current class also named IxiaNgpf
            from ixiaerror import IxiaError
        except ImportError as e:
            raise ImportError(
                "IXIA environment variables incorrect. "
                "Ensure version key for Ixia/IxNetwork VM device in testbed YAML is set"
            ) from e

        # Init class variables
        self.ixiatcl = IxiaTcl()
        self.ixiahlt = IxiaHlt(self.ixiatcl)
        self.ixiangpf = IxiaNgpfft(self.ixiahlt)
        self.ixNet = self.ixiangpf.ixnet  # For low level Python API commands

        self._is_connected = False
        self.virtual_ports = []
        self._genie_view = None
        self._genie_page = None
        self._golden_profile = PrettyTable()
        self._flow_statistics_table = PrettyTable()
        self._traffic_statistics_table = PrettyTable()
        # Valid QuickTests (to be expanded as tests have been validated)
        self.valid_quicktests = [
            "rfc2544frameLoss",
            "rfc2544throughput",
            "rfc2544back2back",
        ]
        # Type of traffic configured
        self.config_type = None
        if "chassis" not in self.connection_info:
            self.connection_info["chassis"] = []

        # Get Ixia device arguments from testbed YAML file
        for key in [
            "ixnetwork_api_server_ip",
            "ixnetwork_tcl_port",
            "ixia_port_list",
            "ixnetwork_version",
            "ixia_chassis_ip",
            "ixia_license_server_ip",
            "chassis",
            "reset",
        ]:
            # Verify Ixia ports provided are a list
            if (
                key == "ixia_port_list"
                and key in self.connection_info
                and not isinstance(self.connection_info[key], list)
            ):
                log.error("Attribute '{}' is not a list as expected".format(key))

            if key in self.connection_info:
                setattr(self, key, self.connection_info[key])
            else:
                log.warning(
                    "Argument '{k}' is not found in testbed "
                    "YAML for device '{d}'".format(k=key, d=self.device.name)
                )

        self.device = self.device or kwargs.get("device")
        self.via = kwargs.get("via", "tgn")

        creds = self.device.credentials
        self.username = creds.get("default", {}).get("username")
        self.password = creds.get("default", {}).get("password")
        if isinstance(self.password, SecretString):
            self.password = to_plaintext(self.password)

        # Ixia Chassis Details
        header = "Ixia Chassis Details"
        summary = Summary(title=header, width=48)
        summary.add_message(
            msg="IxNetwork API Server: {}".format(self.ixnetwork_api_server_ip)
        )
        summary.add_sep_line()
        summary.add_message(msg="IxNetwork Version: {}".format(self.ixnetwork_version))
        summary.add_sep_line()
        if self.chassis:
            summary.add_message(
                msg="Ixia Multi Chassis: {}".format([c["ip"] for c in self.chassis])
            )
            summary.add_sep_line()
        else:
            summary.add_message(msg="Ixia Chassis: {}".format(self.ixia_chassis_ip))
            summary.add_sep_line()
        summary.add_message(
            msg="Ixia License Server: {}".format(self.ixia_license_server_ip)
        )
        summary.add_sep_line()
        summary.add_message(
            msg="Ixnetwork TCL Port: {}".format(self.ixnetwork_tcl_port)
        )
        summary.add_sep_line()
        # Handle reset which is implemented as a flag in tcl
        try:
            summary.add_message(msg="Reset flag: {}".format(self.reset))
        # default on so any existing IxNetwork session is reset
        except AttributeError as e:
            summary.add_message(msg="Reset flag: 1")
        summary.add_sep_line()
        # SSH Tunnel support for ixianative
        try:
            if self.connection_info["sshtunnel"]:
                summary.add_message(
                    msg="SSH Tunnel required to server: {}".format(
                        self.connection_info["sshtunnel"]["host"]
                    )
                )
                summary.add_sep_line()
        except KeyError:
            pass
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to extract ssh tunne connection info ") from e
        #
        summary.print()

        # Genie Traffic Documentation
        url = get_url().replace("genie", "genietrafficgen")
        log.info(
            "For more information, see Genie traffic documentation: "
            "{}/ixianative.html".format(url)
        )

    @BaseConnection.locked
    def connect(self):
        """Connect to Ixia"""
        log.info(banner("Connecting to IXIA"))

        apiKey = None
        if self.username and self.password:
            try:
                apiKey = self.ixNet.getApiKey(
                    self.ixnetwork_api_server_ip,
                    "-username",
                    self.username,
                    "-password",
                    self.password,
                )
            except IxNetError as e:
                log.warning(e)

        # we go with a dict instead of list since we want to keep the named arguments
        # ixia ngpf specically requires IP:port convention
        connect_args = {
            "ixnetwork_tcl_server": self.ixnetwork_api_server_ip
            + ":"
            + str(self.ixnetwork_tcl_port),
            "tcl_server": self.ixia_chassis_ip,
            "device": self.ixia_chassis_ip,
            "port_list": self.ixia_port_list,
            "break_locks": 1,
            "connect_timeout": 30,
        }

        # SSH Tunnel support for ixianative
        try:
            if self.connection_info["sshtunnel"]:
                from unicon.sshutils import sshtunnel

                tunnel_port = sshtunnel.auto_tunnel_add(self.device, self.via)
                tunnel_ip = self.device.connections[self.via]["sshtunnel"]["tunnel_ip"]
                log.info(
                    "Connecting to Ixia via SSH tunnel IP '{}' and port '{}'".format(
                        tunnel_ip, tunnel_port
                    )
                )
                #
                connect_args = {
                    "ixnetwork_tcl_server": str(tunnel_ip) + ":" + str(tunnel_port),
                    "tcl_server": self.ixia_chassis_ip,
                    "device": self.ixia_chassis_ip,
                    "port_list": self.ixia_port_list,
                    "break_locks": 1,
                    "connect_timeout": 30,
                }
        except KeyError:
            pass  # nothing happens, proceed with no SSH tunnel
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Failed to create SSH tunnel") from e
        #
        if apiKey:
            connect_args["api_key"] = apiKey
        try:
            if self.reset:
                connect_args["reset"] = 1  # reset explicitly set to 1 in testbed yaml
        except AttributeError as e:
            log.info("reset not specified in testbed yaml")
            pass  # absent from testbed yaml
        except Exception as e:
            log.error(e)
            raise GenieTgnError("Error with self.reset flag") from e

        # Execute connect on IxNetwork
        try:
            connect_status = self.ixiangpf.connect(
                **connect_args
            )  # ** since connect_args is a dict
        except Exception as e:
            log.error(e)
            raise GenieTgnError(
                "Failed to connect to device '{d}' on port '{p}'".format(
                    d=self.device.name, p=self.ixnetwork_tcl_port
                )
            ) from e
        # Verify return
        try:
            assert connect_status["status"] == self.ixiahlt.SUCCESS
            log.debug(connect_status)
        except AssertionError as e:
            log.error(connect_status)
            # err = self.ixiatcl.tcl_error_info()
            # log.error(err)
            raise GenieTgnError(
                "Failed to connect to device '{d}' on port '{p}'".format(
                    d=self.device.name, p=self.ixnetwork_tcl_port
                )
            ) from e
        else:
            self._is_connected = True
            log.info(
                "Connected to IxNetwork API server on TCL port '{p}'".format(
                    d=self.device.name, p=self.ixnetwork_tcl_port
                )
            )

    def isconnected(func):
        """Decorator to make sure session to device is active

        There is limitation on the amount of time the session can be active
        to IxNetwork API server. However, there are no way to verify if the
        session is still active unless we test sending a command.
        """

        @wraps(func)
        def decorated(self, *args, **kwargs):
            # Check if connected
            try:
                log.propagate = False
                self.ixNet.getAttribute("/globals", "-buildNumber")
            except Exception:
                self.connect()
            finally:
                log.propagate = True
            return func(self, *args, **kwargs)

        return decorated

    def test(self, x, y=1, z=None):
        """Test method"""
        return x + y + z

    @BaseConnection.locked
    @isconnected
    def topology_config(
        self,
        topology_name="",
        port_handle="",
        topology_handle="",
        mode="config",
        device_group_name="",
        device_group_multiplier="10",
        device_group_enabled="1",
    ):
        '''
        Configure topology under Scenario
        e.g.

        .. code-block:: python

            _result_ = self.ixiangpf.topology_config(
                topology_name      = """Topology 1""",
                port_handle        = "1/3/10",
            )
        '''

        # topology_name
        if topology_name:
            try:
                _result_ = self.ixiangpf.topology_config(
                    topology_name=topology_name,
                    port_handle=port_handle,
                )
                log.info(
                    "Configured topology '{t}'on port_handle '{p}'".format(
                        t=topology_name, p=port_handle
                    )
                )

            except Exception as e:
                raise GenieTgnError(
                    "Unable to configure topology '{t}'on port_handle '{p}'".format(
                        t=topology_name, p=port_handle
                    )
                )

            log.info(_result_)
            try:
                assert _result_["status"] == self.ixiahlt.SUCCESS
            except AssertionError as e:
                log.error(_result_)
                raise GenieTgnError(
                    "Failed to configure topology '{t}'on port_handle '{p}'".format(
                        t=topology_name, p=port_handle
                    )
                ) from e

            return _result_["topology_handle"]

        # Additionally if topology_handle is input, continue and return device group handle
        if topology_handle:
            try:
                _result_ = self.ixiangpf.topology_config(
                    topology_handle=topology_handle,
                    device_group_name=device_group_name,
                    device_group_multiplier=str(device_group_multiplier),
                    device_group_enabled=str(device_group_enabled),
                )
                log.info(
                    "Configured topology handle '{t}'"
                    "with device_group_name '{d}'".format(
                        t=topology_handle, d=device_group_name
                    )
                )

            except Exception as e:
                raise GenieTgnError(
                    "Unable to configure topology handle '{t}'"
                    "with device_group_name '{d}'".format(
                        t=topology_handle, d=device_group_name
                    )
                )

            log.info(_result_)
            try:
                assert _result_["status"] == self.ixiahlt.SUCCESS
            except AssertionError as e:
                log.error(_result_)
                raise GenieTgnError(
                    "Failed to configure topology handle '{t}'"
                    "with device_group_name '{d}'".format(
                        t=topology_handle, d=device_group_name
                    )
                ) from e

            return _result_["device_group_handle"]

        else:
            raise GenieTgnError("Invalid input arguments to this function")

    @BaseConnection.locked
    @isconnected
    def multivalue_config(
        self,
        pattern="counter",
        counter_start="1.1.1.1",
        counter_step="0.0.0.1",
        counter_direction="increment",
        nest_step="0.1.0.0",
        nest_owner="topology_handle",
        nest_enabled="1",
    ):
        """
        Generic NGPF multivalue_config function can be used for Layer2 MAC addresses and Layer3 IPv4/6 etc.
        """

        try:
            _result_ = self.ixiangpf.multivalue_config(
                pattern=pattern,
                counter_start=counter_start,
                counter_step=counter_step,
                counter_direction=counter_direction,
                nest_step="%s" % (nest_step),
                nest_owner="%s" % (nest_owner),
                nest_enabled="%s" % (nest_enabled),
            )
        except Exception as e:
            log.error(str(e))
            raise GenieTgnError("Unable to multivalue_config")

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(e)
            raise GenieTgnError("Failed to multivalue_config") from e

        multivalue_handle = _result_["multivalue_handle"]
        return multivalue_handle

    @BaseConnection.locked
    @isconnected
    def interface_config_ethernet(
        self,
        protocol_name="Ethernet 1",
        protocol_handle="deviceGroup_handle",
        mtu="1500",
        src_mac_addr="multivalue_handle",
        vlan="0",
        vlan_id="1",
        vlan_id_step="0",
        vlan_id_count="1",
        vlan_tpid="0x8100",
        vlan_user_priority="0",
        vlan_user_priority_step="0",
        use_vpn_parameters="0",
        site_id="0",
    ):
        """
        Configure an interface with Ethernet information
        Important input is the mac address information multivalue_handle returned from multivalue_config()
        """

        try:
            _result_ = self.ixiangpf.interface_config(
                protocol_name=protocol_name,
                protocol_handle=protocol_handle,
                mtu=mtu,
                src_mac_addr=src_mac_addr,
                vlan=vlan,
                vlan_id=vlan_id,
                vlan_id_step=vlan_id_step,
                vlan_id_count=vlan_id_count,
                vlan_tpid=vlan_tpid,
                vlan_user_priority=vlan_user_priority,
                vlan_user_priority_step=vlan_user_priority_step,
                use_vpn_parameters=use_vpn_parameters,
                site_id=site_id,
            )
        except Exception as e:
            raise GenieTgnError("Unable to interface_config_ethernet")

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(_result_)
            raise GenieTgnError("Failed to interface_config_ethernet") from e

        ethernet_handle = _result_["ethernet_handle"]
        return ethernet_handle

    @BaseConnection.locked
    @isconnected
    def interface_config_ipv4(
        self,
        protocol_name="IPv4 1",
        protocol_handle="ethernet_handle",
        ipv4_multiplier="1",
        ipv4_resolve_gateway="1",
        ipv4_manual_gateway_mac="00.00.00.00.00.01",
        ipv4_manual_gateway_mac_step="00.00.00.00.00.00",
        ipv4_enable_gratarprarp="0",
        ipv4_gratarprarp="gratarp",
        gateway="10.10.10.1",
        gateway_step="0.0.0.0",
        intf_ip_addr="multivalue_handle",
        netmask="255.255.255.0",
        wait_time=10,
    ):
        """
        Configure an interface with IPv4 information
        Input ethernet_handle from interface_config_ethernet() and IP information from multivalue_config()
        """
        try:
            _result_ = self.ixiangpf.interface_config(
                protocol_name=protocol_name,
                protocol_handle=protocol_handle,
                ipv4_multiplier=ipv4_multiplier,
                ipv4_resolve_gateway=ipv4_resolve_gateway,
                ipv4_manual_gateway_mac=ipv4_manual_gateway_mac,
                ipv4_manual_gateway_mac_step=ipv4_manual_gateway_mac_step,
                ipv4_enable_gratarprarp=ipv4_enable_gratarprarp,
                ipv4_gratarprarp=ipv4_gratarprarp,
                gateway=gateway,
                gateway_step=gateway_step,
                intf_ip_addr=intf_ip_addr,
                netmask=netmask,
            )
        except Exception as e:
            raise GenieTgnError("Unable to interface_config_ipv4")

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(_result_)
            raise GenieTgnError("Failed to interface_config_ipv4") from e

        ipv4_handle = _result_["ipv4_handle"]

        # Wait
        log.info(
            "Waiting for '{}' seconds after interface_config_ipv4...".format(wait_time)
        )
        time.sleep(wait_time)

        return ipv4_handle

    @BaseConnection.locked
    @isconnected
    def test_control(self, action="start_all_protocols", handle="", wait_time=10):
        """
        test_control
        Various actions: common ones include start_all_protocols stop_all_protocols
                -action             CHOICES start_all_protocols
                                    CHOICES stop_all_protocols
                                    CHOICES restart_down
                                    CHOICES start_protocol
                                    CHOICES stop_protocol
                                    CHOICES abort_protocol
                                    CHOICES apply_on_the_fly_changes
                                    CHOICES check_link_state
                                    CHOICES get_all_qt_handles
                                    CHOICES get_available_qt_types
                                    CHOICES get_qt_handles_for_type
                                    CHOICES qt_remove_test
                                    CHOICES qt_apply_config
                                    CHOICES qt_start
                                    CHOICES qt_run
                                    CHOICES qt_stop
                                    CHOICES qt_wait_for_test
                                    CHOICES is_done
                                    CHOICES wait
                                    CHOICES get_result
                                    CHOICES qt_get_input_params
                                    CHOICES configure_all
        """

        test_control_args = {"action": action}
        if handle:
            test_control_args["handle"] = handle
        log.info(test_control_args)

        try:
            _result_ = self.ixiangpf.test_control(**test_control_args)
        except Exception as e:
            raise GenieTgnError(
                "Unable to test_control with action {a} and handle {h}".format(
                    a=action, h=handle
                )
            )

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(_result_)
            raise GenieTgnError(
                "Failed to test_controlwith action {a} and handle {h}".format(
                    a=action, h=handle
                )
            ) from e

        # Wait
        log.info("Waiting for '{}' seconds after test_control...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def traffic_config(
        self,
        mode="create",
        emulation_src_handle="topo1_hndl",
        emulation_dst_handle="topo2_hndl",
        src_dest_mesh="one_to_one",
        route_mesh="one_to_one",
        track_by="traffic_item",
        bidirectional="1",
        name="Traffic_Item_1",
        frame_size="512",
        rate_pps="1000",
        circuit_endpoint_type="ipv4",
    ):
        """
        traffic_config
        Create traffic items with streams
        """

        try:
            _result_ = self.ixiangpf.traffic_config(
                mode=mode,
                emulation_src_handle=emulation_src_handle,
                emulation_dst_handle=emulation_dst_handle,
                src_dest_mesh=src_dest_mesh,
                route_mesh=route_mesh,
                track_by=track_by,
                bidirectional=bidirectional,
                name=name,
                frame_size=frame_size,
                rate_pps=rate_pps,
                circuit_endpoint_type=circuit_endpoint_type,
            )

        except Exception as e:
            raise GenieTgnError("Unable to traffic_config")

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(_result_)
            raise GenieTgnError("Failed to traffic_config") from e

        traffic_stream_id = _result_["stream_id"]
        return traffic_stream_id

    @BaseConnection.locked
    @isconnected
    def traffic_control(
        self, action="stop", handle="", wait_time=10, packet_loss_duration_enable=False
    ):
        """
        traffic_control
        Valid values are: "sync_run|run|manual_trigger|stop|poll|reset|destroy|clear_stats|regenerate|apply"
        """

        traffic_control_args = {"action": action}
        if handle:
            traffic_control_args["handle"] = handle

        log.info(traffic_control_args)

        try:
            _result_ = self.ixiangpf.traffic_control(**traffic_control_args)
            log.info(
                "Executed traffic_control with action {a} and handle {h}".format(
                    a=action, h=handle
                )
            )
        except Exception as e:
            raise GenieTgnError(
                "Unable to traffic_control with action {a} and handle {h}".format(
                    a=action, h=handle
                )
            )

        # Special usecase to explicitly enable packet_loss_duration_enable which is very useful
        # Make this call before traffic_config with mode: 'create' to enable this
        # e.g. ixia.traffic_control(action='reset', wait_time=5, packet_loss_duration_enable=True)
        # Then ixia.traffic_config(mode='create', -> etc.
        if packet_loss_duration_enable:
            try:
                _result_ = self.ixiangpf.traffic_control(
                    action="reset",
                    traffic_generator="ixnetwork_540",
                    cpdp_convergence_enable="0",
                    l1_rate_stats_enable="1",
                    misdirected_per_flow="0",
                    delay_variation_enable="0",
                    packet_loss_duration_enable="1",
                    latency_enable="1",
                    latency_bins="enabled",
                    latency_control="store_and_forward",
                    instantaneous_stats_enable="0",
                )

                log.info(
                    "Executed traffic_control with packet_loss_duration_enable"
                    "with action {a} and handle {h}".format(a=action, h=handle)
                )
            except Exception as e:
                raise GenieTgnError(
                    "Unable to traffic_control with action {a} and handle {h}".format(
                        a=action, h=handle
                    )
                )

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(_result_)
            raise GenieTgnError(
                "Failed to traffic_controlwith action {a} and handle {h}".format(
                    a=action, h=handle
                )
            ) from e

        # Wait
        log.info("Waiting for '{}' seconds after traffic_control...".format(wait_time))
        time.sleep(wait_time)

    @BaseConnection.locked
    @isconnected
    def traffic_stats(self, mode="traffic_item", wait_time=5):
        """
        traffic_stats
        Valid values for mode are: "all|aggregate|flow|l23_test_summary|stream|streams|traffic_item|L47_traffic_item"
        There's more too check the TCL documentation for all

        Returns a dictionary with all the stats
        """

        try:
            _result_ = self.ixiangpf.traffic_stats(mode=mode)
        except Exception as e:
            raise GenieTgnError(
                "Unable to get traffic_stats with mode {m}".format(m=mode)
            )

        log.info(_result_)
        try:
            assert _result_["status"] == self.ixiahlt.SUCCESS
        except AssertionError as e:
            log.error(_result_)
            raise GenieTgnError(
                "Failed to traffic_statswith mode {m}".format(m=mode)
            ) from e

        return _result_
