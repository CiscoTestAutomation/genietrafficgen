.. _ixianative:

Ixia Native
===========

``Genie`` can connect to Ixia traffic generator devices that are running
IxNetwork API server versions 7.40 or higher. Refer to the user guide below for
detailed information on using ``Genie`` to control Ixia using the public PyPI
Package IxNetwork.


System Requirements
-------------------

1. Ixia chassis with ports and active Ixia licenses
2. IxNetwork API server version 7.40 or higher (running standalone or within Ixia chassis)
3. Installed :ixnetwork_pypi:`ixnetwork<http>` PyPI package (version 8.50.1501.9+)

Ixia Libraries
^^^^^^^^^^^^^^

It is recommended to check the :ixiasupport:`Ixia Versions Support <http>` page
to download the Ixia libraries corresponding to the user's Ixia chassis and the
version of the IxNetwork API server application they are running.

For further information, please reach out to your Ixia representative.


Adding Ixia device
------------------

An Ixia traffic generator `device` can be specified in the ``testbed`` YAML file
as shown in the example below:

.. code-block:: yaml

    devices:
      IXIA:
        type: tgn
        os: 'ixianative'
        connections:
          tgn:
            class: genie.trafficgen.ixianative.IxiaNative
            ixnetwork_api_server_ip: 172.25.195.91
            ixnetwork_tcl_port: 8012
            ixnetwork_version: '8.10'
            ixia_chassis_ip: 172.27.101.96
            ixia_license_server_ip: 172.27.101.96
            ixia_port_list: ['9/6', '9/7']

It is **mandatory** to specify a connection named 'tgn' along with the 
connection manager details for the Ixia device in the testbed YAML file as shown
in the example above.

OS `ixianative` uses an IxNetwork native Python based connection library:
`genie.trafficgen.ixianative.IxiaNative`

.. tip::

    1. The `type` key must be set to "tgn".
    2. The `os` key specifies which OS implementation to use to connect to this
       device. Use "ixianative" for IxNetwork native.
    3. The `connections` key specifies the connection label which **must**
       contain a connection labelled `tgn`.

The following are mandatory keys to be provided in the `testbed` YAML while
defining an Ixia `device`:

.. code-block:: text

    +--------------------------------------------------------------------------+
    | Ixia Testbed YAML Parameters                                             |
    +==========================================================================+
    | Argument                 | Description                                   |
    |--------------------------+-----------------------------------------------|
    | class                    | Connection class implementation information.  |
    |--------------------------+-----------------------------------------------|
    | ixnetwork_api_server_ip  | IP address of server running IxNetwork EA     |
    |                          | App/GUI. Can be running within chassis or on  |
    |                          | standalone server.                            |
    |--------------------------+-----------------------------------------------|
    | ixnetwork_tcl_port       | TCL port of IxNetwork API server.             |
    |--------------------------+-----------------------------------------------|
    | ixnetwork_version        | Version of IxNetwork API server.              |
    |--------------------------+-----------------------------------------------|
    | ixia_chassis_ip          | IP address of Ixia chassis.                   |
    |--------------------------+-----------------------------------------------|
    | ixia_license_server_ip   | IP address of Ixia licensing server.          |
    |--------------------------+-----------------------------------------------|
    | ixia_port_list           | List of Ixia ports for testbed topology to be |
    |                          | used by Genie.                                |
    +==========================================================================+

.. note::

    If Ixia is not the preferred traffic generator, users can also write a new
    connection class implementation for their traffic generator device.


Connect to Ixia device
----------------------

After specifying the Ixia `device` in the `testbed` YAML file, we can connect to
the device using the `connect()` method:

.. code-block:: python

    # Load testbed containing Ixia
    >> from genie.conf import Genie
    >> testbed = Genie.init('/path/to/testbed_with_tgn.yaml')

    # Specify the Ixia
    >> dev = testbed.devices['IXIA']

    # Connect to Ixia
    >>> dev.connect(via='tgn')
    If you are trying to connect to a Windows IxNetwork API server on TCL port you can safely ignore this warning.
    WARNING: IxNetwork Python library version 8.50.1501.9 is not matching the IxNetwork client version 8.10.1046.6


Traffic Generator Methods
-------------------------

The following table contains a list of available methods/actions to perform on
an Ixia traffic generator device:


.. code-block:: text

    +----------------------------------------------------------------------------------+
    | Traffic Generator Methods                                                        |
    +==================================================================================+
    | Methods                         | Description                                    |
    |---------------------------------+------------------------------------------------|
    | connect                         | Connect to Ixia traffic generator device.      |
    |                                 | Arguments:                                     |
    |                                 |   * [O] alias - In testbed YAML.               |
    |                                 |   * [O] via - In mapping datafile.             |
    |---------------------------------+------------------------------------------------|
    | load_configuration              | Loads the configuration onto Ixia device.      |
    |                                 | Arguments:                                     |
    |                                 |   * [M] configuration - static configuration   |
    |                                 |         file for Ixia.                         |
    |                                 |   * [O] wait_time - time to wait after loading |
    |                                 |         configuration file.                    |
    |                                 |         Default: 60 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | start_all_protocols             | Starts all protocols on Ixia device.           |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after starting|
    |                                 |         all protocols on Ixia.                 |
    |                                 |         Default: 60 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | stop_all_protocols              | Stops all protocols on Ixia device.            |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after stopping|
    |                                 |         all protocols on Ixia.                 |
    |                                 |         Default: 60 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | apply_traffic                   | Apply L2/L3 traffic on Ixia device.            |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after applying|
    |                                 |         L2/L3 traffic on Ixia.                 |
    |                                 |         Default: 60 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | send_arp                        | Send ARP to all interfaces from Ixia device.   |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after sending |
    |                                 |         ARP to all interfaces (in seconds).    |
    |                                 |         Default: 10 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | send_ns                         | Send NS to all interfaces from Ixia device.    |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after sending |
    |                                 |         NS packet to all interfaces from Ixia. |
    |                                 |         Default: 10 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | start_traffic                   | Starts L2/L3 traffic on Ixia device.           |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after starting|
    |                                 |         L2/L3 traffic on Ixia.                 |
    |                                 |         Default: 60 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | stop_traffic                    | Stops L2/L3 traffic on Ixia device.            |
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after stopping|
    |                                 |         L2/L3 traffic on Ixia.                 |
    |                                 |         Default: 60 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | clear_statistics                | Clears L2/L3 traffic statistics on Ixia device.|
    |                                 | Arguments:                                     |
    |                                 |   * [O] wait_time - time to wait after clearing|
    |                                 |         protocol and traffic statistics on Ixia|
    |                                 |         Default: 10 (seconds)                  |
    |---------------------------------+------------------------------------------------|
    | check_traffic_loss              | Checks all traffic streams for traffic loss.   |
    |                                 | Arguments:                                     |
    |                                 |   * [O] loss_tolerance - max % of traffic loss |
    |                                 |         allowed. Default: 10%.                 |
    |                                 |   * [O] check_interval - wait time between     |
    |                                 |         traffic loss checks on Ixia.           |
    |                                 |         Default: 30 (seconds)                  |
    |                                 |   * [O] check_iteration - max iterations for   |
    |                                 |         traffic loss checks. Default: 10.      |
    |---------------------------------+------------------------------------------------|
    | create_traffic_profile          | Returns a 'profile' of traffic streams that are|
    |                                 | configured on Ixia as a Python PrettyTable.    |
    |                                 | Arguments:                                     |
    |                                 |     * [O] set_golden - sets the traffic profile|
    |                                 |           created to be the "golden" profile   |
    |                                 |           for the current run.                 |
    |                                 |     * [O] clear_stats_time - wait time after   |
    |                                 |           clearing protocol, traffic statistics|
    |                                 |           while creating traffic profile.      |
    |                                 |           Default: 60 (seconds)                |
    |                                 |     * [O] view_create_interval - wait time for |
    |                                 |           checking if custom traffic items view|
    |                                 |           "GENIE" is ready to create profile.  |
    |                                 |           Default: 30 (seconds)                |
    |                                 |     * [O] view_create_iteration - max iteration|
    |                                 |           for checking if custom traffic items |
    |                                 |           view is ready. Default: 10.          |
    |---------------------------------+------------------------------------------------|
    | get_golden_profile              | Returns the "golden" traffic profile in Python |
    |                                 | PrettyTable format. If not set, returns empty  |
    |                                 | table.                                         |
    |---------------------------------+------------------------------------------------|
    | set_ixia_virtual_ports          | 
    |---------------------------------+------------------------------------------------|
    | get_ixia_virtual_port           |
    |---------------------------------+------------------------------------------------|
    | get_ixia_virtual_port_attribute |
    |---------------------------------+------------------------------------------------|
    | get_traffic_streams             |
    |---------------------------------+------------------------------------------------|
    | get_traffic_stream_data         |
    |---------------------------------+------------------------------------------------|
    | set_traffic_stream_data         |
    |---------------------------------+------------------------------------------------|
    | enable_data_packet_capture      |
    |---------------------------------+------------------------------------------------|
    | disable_data_packet_capture     |
    |---------------------------------+------------------------------------------------|
    | enable_control_packet_capture   |
    |---------------------------------+------------------------------------------------|
    | disable_control_packet_capture  |
    |---------------------------------+------------------------------------------------|
    | start_packet_capture            | Starts packet capture (PCAP) on enabled ports. |
    |                                 | Arguments:                                     |
    |                                 |     * [O] capture_time - Time to wait while    |
    |                                 |           packet capture is occurring.         |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_packet_capture             | Stops packet capture (PCAP) on enabled ports.  |
    |---------------------------------+------------------------------------------------|
    | get_packet_capture_count        | Returns the total number of packets captured   |
    |                                 | during a packet capture session on a specific  |
    |                                 | port of a specified type of capture.           |
    |                                 | Arguments:                                     |
    |                                 |     * [M] port_name - port on which packet     |
    |                                 |           capture session was performed.       |
    |                                 |     * [M] pcap_type - specify either data or   |
    |                                 |           control packet capture type.         |
    |---------------------------------+------------------------------------------------|
    | get_packet_capture_data         | Extracts and displays all data from a packet   |
    |                                 | capture session on a specified port.           |
    |                                 | Arguments:                                     |
    |                                 |     * [M] port_name - port on which packet     |
    |                                 |           capture session was performed.       |
    |---------------------------------+------------------------------------------------|
    | save_packet_capture_file        | Saves the packet capture file as specified     |
    |                                 | filename to desired location.                  |
    |                                 | Arguments:                                     |
    |                                 |     * [M] port_name - port on which packet     |
    |                                 |           capture session was performed.       |
    |                                 |     * [M] pcap_type - specify either data or   |
    |                                 |           control packet capture type.         |
    |                                 |     * [M] filename - destination filename to   |
    |                                 |           save packet capture file on IxNetwork|
    |                                 |           API server.                          |
    |                                 |     * [O] directory - destination directory to |
    |                                 |           save packet capture file on IxNetwork|
    |                                 |           API server.                          |
    |                                 |           Default: C:/ on windows server       |
    |---------------------------------+------------------------------------------------|
    | copy_packet_capture_file        | Copy packet capture file as specified filename |
    |                                 | to desired location outside IxNetwork API      |
    |                                 | server host.                                   |
    |                                 | Arguments:                                     |
    |                                 |     * [M] src_file - location of packet capture|
    |                                 |           on host IxNetwork API server.        |
    |                                 |     * [M] dest_file - location to copy the     |
    |                                 |           packet capture file outside the      |
    |                                 |           IxNetwork API server.                |
    +==================================================================================+

The methods listed above can be executed directly on an Ixia traffic generator
device from a Python prompt or within ``Genie`` and ``pyATS`` scripts.


Traffic Generator Usage
-----------------------

This sections covers sample usage of executing available Ixia traffic generator
methods (actions) mentioned in the previous section.


.. code-block:: python

    # Load the testbed
    >> from genie.conf import Genie
    >> testbed = Genie.init('/path/to/testbed_with_tgn.yaml')

    # Specify the Ixia device
    >> dev = testbed.devices['IXIA']

    # Connect to the Ixia device
    >> dev.connect(via='tgn')

    # Load configuration file
    >> dev.load_configuratin(configuration='/path/to/ixia_bgp_multicast.ixncfg')

    # Start traffic on the device
    >> dev.start_traffic()

    # Stop traffic on the device
    >> dev.stop_traffic()

    # Clear stats on the device
    >> dev.clear_statistics()


Genie Traffic Subsections
-------------------------

``Genie`` bundles the different steps involved with Ixia setup and configuration
into controllable subsections that can be executed within ``Genie`` harness.

The harness provides the following subsections:
    1. common_setup: initialize_traffic
    2. common_setup: profile_traffic
    3. common_cleanup: stop_traffic

To add/remove execution of the above mentioned subsections simply "enable" or
"disable" them by adding/removing the subsection name from the execution order
key, as shown below:

.. code-block:: yaml

    setup:
      sections:
        connect:
          method: genie.harness.commons.connect
        configure:
          method: genie.harness.commons.configure
        configuration_snapshot:
          method: genie.harness.commons.check_config
        save_bootvar:
          method: genie.libs.sdk.libs.abstracted_libs.subsection.save_bootvar
        learn_system_defaults:
          method: genie.libs.sdk.libs.abstracted_libs.subsection.learn_system_defaults
        initialize_traffic:
          method: genie.harness.commons.initialize_traffic
        profile_traffic:
          method: genie.harness.commons.profile_traffic

      order: ['connect', 'configure', 'initialize_traffic', 'profile_traffic']

    cleanup:
      sections:
        stop_traffic:
          method: genie.harness.commons.stop_traffic

      order: ['stop_traffic']


Genie Harness Traffic Generator Arguments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

User's can specify arguments to control the ``Genie`` harness subsections via:

    1. gRun in the job file as shown below:

    .. code-block:: python

        gRun(config_datafile=os.path.join(test_path, 'config_datafile.yaml'),
             tgn_load_configuration=False,
             tgn_start_protocols=True,
             tgn_traffic_loss_tolerance=15.0)


    2. easypy in command line as shown below:

    .. code-block:: bash

        easypy job.py --testbed-file <testbed yaml> \
                      --tgn-load-configuration True \
                      --tgn-start-protocols False \
                      --tgn-traffic-loss-tolerance 20.0

The table below is a list of arguments that can be configured by the user to control
traffic generator subsections in ``Genie`` harness.

.. code-block:: text

    +--------------------------------------------------------------------------+
    | Genie Harness Traffic Generator Arguments                                |
    +==========================================================================+
    | Argument                         | Description                           |
    |----------------------------------+---------------------------------------|
    | tgn-port-list                    | Modify the Ixia ports list to connect |
    |                                  | to, from the existing ixia_port_list  |
    |                                  | Default: []                           |
    |----------------------------------+---------------------------------------|
    | tgn-load-configuration           | Enable/disable loading static config  |
    |                                  | file on Ixia in 'initialize_traffic'  |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-load-configuration-time      | Time to wait after loading config     |
    |                                  | on Ixia during 'initialize_traffic'   |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-start-protocols              | Enable/disable starting protocols on  |
    |                                  | Ixia during 'initialize_traffic'      |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-protocols-convergence-time   | Time to wait for all traffic streams  |
    |                                  | converge to steady state in           |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 120 (seconds)                |
    |----------------------------------+---------------------------------------|
    | tgn-stop-protocols-time          | Time to wait after stopping protocols |
    |                                  | on Ixia during 'stop_traffic'         |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-apply-traffic                | Enable/disable applying L2/L3 traffic |
    |                                  | on Ixia in 'initialize_traffic'       |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-apply-traffic-time           | Time to wait after applying L2/L3     |
    |                                  | traffic in 'initialize_traffic'       |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-send-arp                     | Enable/disable send ARP to interfaces |
    |                                  | from Ixia in 'initialize_traffic'     |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-arp-wait-time                | Time to wait after sending ARP from   |
    |                                  | Ixia in 'initialize_traffic'          |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-send-ns                      | Enable/disable send NS to interfaces  |
    |                                  | on Ixia in 'initialize_traffic'       |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-ns-wait-time                 | Time to wait after sending NS packet  |
    |                                  | from Ixia in 'initialize_traffic'     |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-start-traffic                | Enable/disable starting L2/L3 traffic |
    |                                  | on Ixia in 'initialize_traffic'       |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-steady-state-convergence-time| Time to wait for traffic streams to   |
    |                                  | converge to steady state after start  |
    |                                  | traffic in 'initialize_traffic'       |
    |                                  | Default: 15 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-stop-traffic-time            | Time to wait after stopping traffic   |
    |                                  | streams in 'stop_traffic'             |
    |                                  | Default: 15 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-clear-statistics             | Enable/disable clearing protocol and  |
    |                                  | traffic statistics on Ixia in         |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-clear-stats-time             | Time to wait after clearing protocol  |
    |                                  | and traffic statistics on Ixia in     |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-check-traffic-loss           | Enable/disable checking of frames loss|
    |                                  | and traffic loss for all configured   |
    |                                  | traffic streams after starting L2/L3  |
    |                                  | traffic on Ixia in'initialize_traffic'|
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-traffic-loss-tolerance       | Maximum traffic loss % accepted after |
    |                                  | starting traffic on Ixia in           |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 15%                          |
    |----------------------------------+---------------------------------------|
    | tgn-stabilization-interval       | Time to wait between re-checking all  |
    |                                  | configured traffic streams on Ixia for|
    |                                  | traffic loss in 'initialize_traffic'  |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-stabilization-iteration      | Number of attempts to re-check all the|
    |                                  | configured traffic streams on Ixia for|
    |                                  | traffic loss in 'initialize_traffic'  |
    |                                  | Default: 10 attempts                  |
    |----------------------------------+---------------------------------------|
    | tgn-golden-profile               | Full path to the text file containing |
    |                                  | previously verified and saved traffic |
    |                                  | profile to compare it against in      |
    |                                  | 'profile_traffic'                     |
    |                                  | Default: None                         |
    |----------------------------------+---------------------------------------|
    | tgn-view-create-interval         | Time to wait between re-checking if   |
    |                                  | custom traffic items view "GENIE" is  |
    |                                  | ready in 'profile_traffic'            |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-view-create-iteration        | Number of attempts to re-check if the |
    |                                  | custom traffic items view "GENIE" is  |
    |                                  | ready in 'profile_traffic'            |
    |                                  | Default: 10 attempts                  |
    |----------------------------------+---------------------------------------|
    |tgn-profile-traffic-loss-tolerance| Maximum acceptable difference between |
    |                                  | two Genie traffic profile snapshots   |
    |                                  | for loss % column in 'profile_traffic'|
    |                                  | Default: 2%                           |
    |----------------------------------+---------------------------------------|
    | tgn-profile-frames-loss-tolerance| Maximum acceptable difference between |
    |                                  | two Genie traffic profile snapshots   |
    |                                  | for frames delta in 'profile_traffic' |
    |                                  | Default: 5 frames                     |
    |----------------------------------+---------------------------------------|
    | tgn-profile-rate-loss-tolerance  | Maximum acceptable difference between |
    |                                  | two Genie traffic profile snapshots   |
    |                                  | for Tx/Rx rate in 'profile_traffic'   |
    |                                  | Default: 2 pps                        |
    |----------------------------------+---------------------------------------|
    | tgn-logfile                      | Logfile to save all Ixia output       |
    |                                  | Default: 'tgn.log'                    |
    +==========================================================================+


common_setup: initialize_traffic
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This subsection packages the various steps associated with Ixia setup such as
connectiong and loading static configuration, enabling protocols, starting
traffic, etc into one runnable subsection. 

It performs the following steps in order:

    1. Connect to Ixia
    2. Load static configuration onto Ixia
    3. Start all protocols
    4. Apply L2/L3 traffic configuration
    5. Send ARP, NS packet to all interfaces from Ixia
    6. Start L2/L3 traffic
    7. Clear traffic statistics after streams have converged to steady state
    8. Check traffic loss % and frames loss across all configured traffic streams


Step1: Connect to Ixia
""""""""""""""""""""""

Once an Ixia device has been added to the `testbed` YAML file, ``Genie`` harness
can connect to this Ixia `device` via the default connection 'tgn' as shown
below:

.. code-block:: yaml

    devices:
      IXIA:
        type: tgn
        os: 'ixianative'
        connections:
          tgn:
            class: genie.trafficgen.ixianative.IxiaNative


Step2: Load static configuration onto Ixia
""""""""""""""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-load-configuration`.

``Genie`` can load a static configuration file onto the Ixia `device` that has
been specified in the `configuration_datafile` as shown below:

.. code-block:: yaml

    devices:
      IXIA:
        1:
          config: /path/to/ixia_bgp_multicast.ixncfg

It waits for `tgn-load-configuration-time` seconds for traffic to be loaded onto
Ixia.


Step3: Start all protocols
""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-start-protocols`.

If this flag is enabled, ``Genie`` harness will start all protocols on the Ixia
device and wait for `tgn-protocols-convergence-time` seconds for all traffic
streams to converge to steady state.


Step4: Apply L2/L3 traffic
""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-apply-traffic`.

If this flag is enabled, ``Genie`` harness will apply L2/L3 traffic on the Ixia
device and wait for `tgn-apply-traffic-time` seconds after applying traffic.


Step5: Send ARP, NS from Ixia
"""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling arguments:
    * `tgn-send-arp` - send ARP to all interfaces from Ixia
    * `tgn-send-ns` - send NS to all interfaces from Ixia

If these flags are enabled, ``Genie`` harness will send ARP and NS to all
interfaces from Ixia. It will wait for `tgn-arp-wait-time` seconds after sending
ARP to all interfaces from Ixia and wait for `tgn-ns-wait-time` seconds after
sending NS packets to all interfaces from Ixia.


Step6: Start L2/L3 traffic
"""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-start-traffic`.

If this flag is enabled, ``Genie`` harness will start L2/L3 traffic on the Ixia
device and wait for `tgn-steady-state-convergence-time` seconds after starting
traffic for all traffic streams to converge to steady state.


Step7: Clear traffic statistics
"""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-clear-statistics`.

If this flag is enabled, ``Genie`` harness will clear all protocol, traffic
statistics on the Ixia device and wait for `tgn-clear-stats-time` seconds after
clearing traffic statistics for traffic collection to resume.


Step8: Check for traffic loss
"""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-check-traffic-loss`.

If this flag is enabled, ``Genie`` harness will verify that all configured
traffic streams have traffic loss within the expected tolerance of 
`tgn-traffic-loss-tolerance` %.

In the event that traffic loss % observed is more than the acceptable tolerance
limit, ``Genie`` will re-check every `tgn-stabilization-interval` seconds upto a
maximum of `tgn-stabilization-iteration` attempts for traffic streams to 
stabilize to steady state; i.e. for traffic loss to lower down to acceptable
tolerance limit. If traffic streams do not stabilize, ``Genie`` marks the traffic
loss check as a failure.


common_setup: profile_traffic
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This subsection packages all the steps associated with "profiling" traffic
streams configured on Ixia.

It creates a custom traffic statistics "view" to create a snapshot/profile of
all configured traffic streams and then saves this profile as the "golden"
profile for the current job/run. This profile is then used as a reference and
compared against traffic profiles created after execution of triggers that are
executed within ``Genie`` harness.

It performs the following steps in order:

    1. Connect to Ixia
    2. Create custom traffic items view named "Genie"
    3. Create a snapshot profile of traffic streams configured on Ixia
    4. Save snapshot profile to Genie job logs
    5. Compare to any previously saved "golden" traffic profile and verify.

While creating the custom traffic items view, ``Genie`` will attempt to check
if the view is ready `tgn-view-create-iteration` times, while waiting for
`tgn-view-create-interval` seconds between each iteration.

To enable/disable execution of this subsection, simply add/remove
'profile_traffic' from the execution order of the 'setup' in the
`subsection_datafile` YAML.

While comparing the current traffic profile to a previously verified "golden"
traffic profile, ``Genie`` will check the following:
    * Maximum acceptable difference between 2 traffic profiles loss% is `tgn-profile-traffic-loss-tolerance`
    * Maximum acceptable difference between 2 traffic profiles frames rate is `tgn-profile-frames-loss-tolerance`
    * Maximum acceptable difference between 2 traffic profiles Tx/Rx rate is `tgn-profile-rate-loss-tolerance`


common_cleanup: stop_traffic
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This subsection stops all protocols and stops traffic on an Ixia `device`.

It performs the following steps in order:

    1. Connect to Ixia
    2. Stop all protocols on Ixia
    3. Stop traffic streams on Ixia

To enable/disable execution of this subsection, simply add/remove 'stop_traffic'
from the execution order of the 'cleanup' in the `subsection_datafile` YAML.

``Genie`` will wait for `tgn-stop-protocols-time` seconds after stopping all
protocols on Ixia for the action to be completed on IxNetwork; it will then wait
for `tgn-stop-traffic-time` seconds after stopping traffic on Ixia for the
action to be completed on IxNetwork.

By default, the traffic is **not** stopped on an Ixia `device` after ``Genie``
execution completes. This is useful for manual debugging on the IxNetwork API
server after ``Genie`` harness job completes.


Genie Traffic Processors
------------------------

A :processors:`processor <http>` is a specific action or collection of actions
that can cumulatively be executed before or after ``Genie`` triggers. Actions
that are performed before a trigger are known as "pre" processors. Actions that
are performed after a trigger are known as "post" processors.

``Genie`` provides traffic related processors that are useful for performing
checks and/or actions on an Ixia traffic generator `device` before or after
executing triggers.


Enabling Processors
^^^^^^^^^^^^^^^^^^^

Enabling execution of ``Genie`` trigger processors can be specified in the
trigger YAML datafile in two ways - either as global processors or local
processors.


Global Processors
"""""""""""""""""

In order to run a processor before/after *all* triggers, user's can mark the
processor as a "global" processor.

This will ensure that the processor runs after every single trigger specified in
the `trigger_group` or `trigger_uids`. This prevents the user from having to
manually list all the processor to execute for each trigger in the
`trigger_datafile` YAML.

Global processors can be specified as follows in the `trigger_datafile` YAML:

.. code-block:: yaml

    global_processors:
      pre:
        clear_traffic_statistics:
          method: genie.harness.libs.prepostprocessor.clear_traffic_statistics
      post:
        check_traffic_loss:
          method: genie.harness.libs.prepostprocessor.check_traffic_loss


Local Processors
""""""""""""""""

In order to run a processor before/after *specific* triggers, users can mark the
processor as a "local" processor.

This will ensure that the processor runs after only the specific triggers that
have procesors listed for them.

Local processors can be specified as follows in the `trigger_datafile` YAML:

.. code-block:: yaml

    TriggerShutNoShutBgp:
      groups: ['bgp']
      processors:
        pre:
          clear_traffic_statistics:
            method: genie.harness.libs.prepostprocessor.clear_traffic_statistics
        post:
          check_traffic_loss:
            method: genie.harness.libs.prepostprocessor.check_traffic_loss
      devices: ['uut']


Disabling Processors
^^^^^^^^^^^^^^^^^^^^

Sometimes pre/post processors are specified as global processors, thereby
informing ``Genie`` harness to execute those processors for all triggers.


It would be tedious and time-consuming if a user wanted to disable a specific
global processor for 1 or a handful of triggers but execute them for all other
triggers. It would require the user to manually add local processors to every
trigger they want to execute.

Instead, users can simply set a trigger level argument `check_traffic` to
"False" to disable execution of any global pre/post traffic processors for that
trigger.

An example of disabling processor 'clear_traffic_statistics' after
TriggerClearBgp is shown below:


.. code-block:: yaml

    global_processors:
      pre:
        clear_traffic_statistics:
          method: genie.harness.libs.prepostprocessor.clear_traffic_statistics
      post:
        check_traffic_loss:
          method: genie.harness.libs.prepostprocessor.check_traffic_loss

    # Disable pre-processor `clear_traffic_statistics` for this trigger

    TriggerClearBgp:
      groups: ['bgp']
      check_traffic: False
      devices: ['uut']

In order to disable local processors, simply remove them from the trigger
definition within the `trigger_datafile` YAML.


processor: clear_traffic_statistics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`clear_traffic_statistics` is a ``Genie`` pre-trigger processor. It clears all
statistics on an Ixia traffic generator `device`, before a trigger is executed.

User's can set optional argument `clear_stats_time` in the `trigger_datafile`
YAML to set how long to wait after clearing statistics on IxNetwork API server
as shown below:

.. code-block:: yaml

      TriggerClearBgp:
        groups: ['bgp']
        devices: ['uut']
        processors:
          pre:
            clear_traffic_statistics:
              method: genie.harness.libs.prepostprocessor.clear_traffic_statistics
              parameters:
                clear_stats_time: 10

The parameters above can also be set at the global processor level.


processor: check_traffic_loss
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`check_traffic_loss` is a ``Genie`` post-trigger processor. It verifies that any
observed traffic loss is within the acceptable loss tolerance and if any frames
loss is within the acceptable frames tolerance, after a trigger is executed.

If a configured traffic stream reports traffic loss that is not within the 
specified tolerance limit for the prescribed number of iterations/checks,
``Genie`` marks the trigger as "failed".

The `check_traffic_loss` post-trigger processor has the following arguments:

1. [Optional] loss_tolerance: Maximum loss % permitted. Default: 15%.
2. [Optional] check_interval: Wait time to re-check traffic/frames loss is within tolerance specified before failing processor. Default: 30 seconds.
3. [Optional] check_iteration: Maximum attempts to verify traffic/frames loss is within tolerance specified before failing processor. Default: 10 attempts.

User's can set arguments for `check_traffic_loss` in the `trigger_datafile`
as shown below:

.. code-block:: yaml

      TriggerClearBgp:
        groups: ['bgp']
        devices: ['uut']
        processors:
          post:
            check_traffic_loss:
              method: genie.harness.libs.prepostprocessor.check_traffic_loss
              parameters:
                loss_tolerance: 15
                check_interval: 60
                check_iteration: 10

The parameters above can also be set at the global processor level.


processor: compare_traffic_profile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`compare_traffic_profile` is a ``Genie`` post-trigger processor. It creates a
snapshot/profile of the traffic streams configured on an Ixia traffic generator
`device` and then compares it to the "golden" snapshot/profile that was created
during the common_setup: initialize_traffic subsection.

The `compare_traffic_profile` post-trigger processor has the following arguments:

1. [Optional] clear_stats: Controls executing clearing of traffic statistics before creating a traffic profile snapshot. Default: True.
2. [Optional] clear_stats_time: Time to wait after clear traffic stats. Default: 30 seconds.
3. [Optional] view_create_interval: Time to wait for custom traffic statistics view 'GENIE' to stabilize (if not previously created & stabilized). Default: 30 seconds.
4. [Optional] view_create_iteration: Maximum attempts to check if traffic statistics view 'GENIE' is stable (if not previously created & stabilized). Default: 10 attempts.
5. [Optional] loss_tolerance: Maximum difference between loss% of both profiles. Default: 2%.
6. [Optional] frames_tolerance: Maximum difference between frames loss of both profiles.Default: 5 frames.
7. [Optional] rate_tolerance: Maximum difference between rate loss of both profiles. Default: 2 pps.

User's can set arguments for `compare_traffic_profile` in the `trigger_datafile`
as shown below:

.. code-block:: yaml

      TriggerClearBgp:
        groups: ['bgp']
        devices: ['uut']
        processors:
          post:
            compare_traffic_profile:
              method: genie.harness.libs.prepostprocessor.compare_traffic_profile
              parameters:
                clear_stats: True
                clear_stats_time: 30
                view_create_interval: 30
                view_create_iteration: 10
                loss_tolerance: 1
                frames_tolerance: 2
                rate_tolerance: 2

The parameters above can also be set at the global processor level.
