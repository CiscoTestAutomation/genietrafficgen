.. _ixianative:

Ixia Native
===========

``genie.trafficgen`` can connect to Ixia traffic generator devices that are running
IxNetwork API server versions 7.50 or higher. Refer to the user guide below for
detailed information on using ``Genie`` to control Ixia using the public PyPI
Package IxNetwork.


System Requirements
-------------------

1. Ixia chassis with ports and active Ixia licenses
2. IxNetwork API server version 7.50 or higher (running standalone or within Ixia chassis)
3. Installed :ixnetwork_pypi:`ixnetwork<http>` PyPI package (version 8.50.1501.9 or higher)

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
            class: genie.trafficgen.TrafficGen
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


Genie Trafficgen Use Cases
---------------------------

The following sections provide sample use cases for performing operations on 
traffic generator devices within your network automation.

Connect to Ixia
^^^^^^^^^^^^^^^

After specifying the Ixia `device` in the `testbed` YAML file, we can connect to
the device using the `connect()` method:

.. code-block:: python

    # Import loader
    >> from genie.testbed import load

    # Load testbed YAML containing Ixia device
    >> testbed = load('/path/to/testbed_with_tgn.yaml')

    >>> testbed
    <Testbed object 'GENIE-TESTBED1' at 0x7fcddcfbe390>

    # Specify the Ixia
    >> dev = testbed.devices['IXIA']

    # Device with name 'IXIA' selected from testbed YAML
    >>> dev
    <Device IXIA at 0x7fcde02e0ac8>

    # Connect to Ixia
    >>> dev.connect(via='tgn')
    +===========================================+
    | Ixia Chassis Details                      |
    +===========================================+
    | IxNetwork API Server: 172.25.195.91       |
    |-------------------------------------------|
    | IxNetwork API Server Platform: Windows    |
    |-------------------------------------------|
    | IxNetwork Version: 8.10                   |
    |-------------------------------------------|
    | Ixia Chassis: 172.27.101.96               |
    |-------------------------------------------|
    | Ixia License Server: 172.27.101.96        |
    |-------------------------------------------|
    | Ixnetwork TCL Port: 8012                  |
    |-------------------------------------------|

    +------------------------------------------------------------------------------+
    |                              Connecting to IXIA                              |
    +------------------------------------------------------------------------------+
    WARNING: IxNetwork Python library version 9.00.1915.16 is not matching the IxNetwork client version 8.10.1046.6
    Connected to IxNetwork API server on TCL port '8012'

.. note::

    If you are trying to connect to a Windows IxNetwork API server on TCL port you can safely ignore this warning.


Load configuration onto Ixia
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates loading a static configuration file onto an Ixia device

.. code-block:: python

    # Load static configuration file
    >>> dev.load_configuration(configuration='/path/to/config.ixncfg')
    +-----------------------------------+
    |        Loading configuration      |
    +-----------------------------------+
    +===================================+
    | Ixia Configuration Information    |
    +===================================+
    | Ixia Ports: ['9/6', '9/7']        |
    |-----------------------------------|
    | File: /path/to/config.ixncfg      |
    |-----------------------------------|
    Loaded configuration file '/path/to/config.ixncfg' onto device 'IXIA'
    Waiting for '60' seconds after loading configuration...
    Verify traffic is in 'unapplied' state after loading configuration
    Traffic in 'unapplied' state after loading configuration onto device 'IXIA'


Applying L2/L3 Traffic on Ixia
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates how to apply loaded traffic on Ixia

.. code-block:: python

    # Apply traffic
    >>> dev.apply_traffic()
    +------------------------------------------------------------------------------+
    |                            Applying L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Applied L2/L3 traffic on device 'IXIA'
    Waiting for '60' seconds after applying L2/L3 traffic...
    Verify traffic is in 'stopped' state...
    Traffic is in 'stopped' state after applying traffic as expected


Start/Stop Routing Protocols on Ixia
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates starting/stopping routing protocols on an Ixia device

.. code-block:: python

        # Start protocols
        >>> dev.start_all_protocols()
        +------------------------------------------------------------------------------+
        |                           Starting routing engine                            |
        +------------------------------------------------------------------------------+
        Started protocols on device 'IXIA
        Waiting for '60' seconds after starting all protocols...

        # Stop protocols
        >>> dev.stop_all_protocols()
        +------------------------------------------------------------------------------+
        |                           Stopping routing engine                            |
        +------------------------------------------------------------------------------+
        Stopped protocols on device 'IXIA'
        Waiting for  '60' seconds after stopping all protocols...


Start/Stop Traffic on Ixia
^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates starting/stopping traffic on an Ixia device

.. code-block:: python

        # Start traffic
        >>> dev.start_traffic()
        +------------------------------------------------------------------------------+
        |                            Starting L2/L3 traffic                            |
        +------------------------------------------------------------------------------+
        Started L2/L3 traffic on device 'IXIA'
        Waiting for '60' seconds after after starting L2/L3 traffic for streams to converge to steady state...
        Checking if traffic is in 'started' state...
        Traffic is in 'started' state

        # Stop traffic
        >>> dev.stop_traffic()
        +------------------------------------------------------------------------------+
        |                            Stopping L2/L3 traffic                            |
        +------------------------------------------------------------------------------+
        Stopped L2/L3 traffic on device 'IXIA'
        Waiting for '60' seconds after after stopping L2/L3 traffic...
        Checking if traffic is in 'stopped' state...
        Traffic is in 'stopped' state


Check for traffic loss on Ixia
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates how to check for traffic loss on an Ixia device

.. code-block:: python

    # Check traffic loss for all configured streams
    >>> dev.check_traffic_loss(check_iteration=1)
    Total number of pages in 'GENIE' view is '1'
    Reading data from 'GENIE' view page 1/1
    +-----------------------+-------------------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    | Source/Dest Port Pair | Traffic Item                  | Tx Frames | Rx Frames | Frames Delta | Tx Frame Rate | Rx Frame Rate | Loss % | Outage (seconds) |
    +-----------------------+-------------------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    | N93_3-N95_1           | ospf                          | 40595     | 0         | 40595        | 50            | 0             | 100    | 811.9            |
    | N93_3-N95_1           | ospfv3                        | 40595     | 0         | 40595        | 50            | 0             | 100    | 811.9            |
    | N93_3-N95_1           | bgp v4                        | 40593     | 0         | 40593        | 49.5          | 0             | 100    | 820.061          |
    +-----------------------+-------------------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+

    Attempt #1: Checking for traffic outage/loss
    +------------------------------------------------------------------------------+
    |                Checking traffic stream: 'N93_3-N95_1 | ospf'                 |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '811.9' seconds is *NOT* within expected maximum outage threshold of '120' seconds
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 100% is *NOT* within maximum expected loss tolerance of 15%
    3. Verify difference between Tx Rate & Rx Rate is less than tolerance threshold of '5' pps
    * Difference between Tx Rate '50' and Rx Rate '0' is *NOT* within expected maximum rate loss threshold of '5' packets per second
    +------------------------------------------------------------------------------+
    |               Checking traffic stream: 'N93_3-N95_1 | ospfv3'                |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '811.9' seconds is *NOT* within expected maximum outage threshold of '120' seconds
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 100% is *NOT* within maximum expected loss tolerance of 15%
    3. Verify difference between Tx Rate & Rx Rate is less than tolerance threshold of '5' pps
    * Difference between Tx Rate '50' and Rx Rate '0' is *NOT* within expected maximum rate loss threshold of '5' packets per second
    +------------------------------------------------------------------------------+
    |               Checking traffic stream: 'N93_3-N95_1 | bgp v4'                |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '820.061' seconds is *NOT* within expected maximum outage threshold of '120' seconds
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 100% is *NOT* within maximum expected loss tolerance of 15%
    3. Verify difference between Tx Rate & Rx Rate is less than tolerance threshold of '5' pps
    * Difference between Tx Rate '49.5' and Rx Rate '0' is *NOT* within expected maximum rate loss threshold of '5' packets per second


Change line rate for given traffic stream
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates how to change the line rate for a given traffic stream

.. code-block:: python

    # Set the line rate for traffic stream 'ospf' to be 30%
    >>> dev.set_line_rate(traffic_stream='ospf', rate=30)
    +------------------------------------------------------------------------------+
    |              Setting traffic stream 'ospf' line rate to '30' %               |
    +------------------------------------------------------------------------------+
    +------------------------------------------------------------------------------+
    |                            Stopping L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Stopped L2/L3 traffic on device 'IXIA'
    Waiting for '15' seconds after after stopping L2/L3 traffic...
    Checking if traffic is in 'stopped' state...
    Traffic is in 'stopped' state
    Successfully changed traffic stream 'ospf' line rate to '30' %
    +------------------------------------------------------------------------------+
    |                         Generating L2/L3 traffic...                          |
    +------------------------------------------------------------------------------+
    -> traffic item 'ospf'
    Waiting for '15' seconds after generating traffic streams
    Checking if traffic is in 'unapplied' state...
    Traffic is in 'unapplied' state
    +------------------------------------------------------------------------------+
    |                            Applying L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Applied L2/L3 traffic on device 'IXIA'
    Waiting for '15' seconds after applying L2/L3 traffic...
    Verify traffic is in 'stopped' state...
    Traffic is in 'stopped' state after applying traffic as expected
    +------------------------------------------------------------------------------+
    |                            Starting L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Started L2/L3 traffic on device 'IXIA'
    Waiting for '15' seconds after after starting L2/L3 traffic for streams to converge to steady state...
    Checking if traffic is in 'started' state...
    Traffic is in 'started' state


Get packet size for given traffic stream
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates how to retreive the packet size for a given traffic stream

.. code-block:: python

    # Get the packet size for traffic stream 'ospf'
    >>> dev.get_packet_size(traffic_stream='ospf')
    '100'

    # Get the packet size for traffic stream 'bgp v4'
    >>> dev.get_packet_size(traffic_stream='bgp v4')
    '100'


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
    |                                 |     * [O] alias - In testbed YAML.             |
    |                                 |     * [O] via - In mapping datafile.           |
    |---------------------------------+------------------------------------------------|
    | disconnect                      | Disconnect from Ixia traffic generator device. |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | load_configuration              | Loads the configuration onto Ixia device.      |
    |                                 | Arguments:                                     |
    |                                 |     * [M] configuration - static configuration |
    |                                 |           file for Ixia.                       |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           loading configuration file.          |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | remove_configuration            | Remove configuration from Ixia device.         |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           removing configuration.              |
    |                                 |           Default: 30 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | save_confiugration              | Saving existing configuration on Ixia into a   |
    |                                 | the specified file.                            |
    |                                 | Arguments:                                     |
    |                                 |     * [M] config_file - Complete write-able    |
    |                                 |           filepath and filename to copy Ixia   |
    |                                 |           configuration to.                    |
    |---------------------------------+------------------------------------------------|
    | start_all_protocols             | Starts all protocols on Ixia device.           |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting all protocols on Ixia.      |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_all_protocols              | Stops all protocols on Ixia device.            |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping all protocols on Ixia.      |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | apply_traffic                   | Apply L2/L3 traffic on Ixia device.            |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           applying L2/L3 traffic on Ixia.      |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | send_arp                        | Send ARP to all interfaces from Ixia device.   |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           sending ARP to all interfaces.       |
    |                                 |           Default: 10 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | send_ns                         | Send NS to all interfaces from Ixia device.    |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           sending NS packet to all interfaces  |
    |                                 |           from Ixia.                           |
    |                                 |           Default: 10 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | start_traffic                   | Starts L2/L3 traffic on Ixia device.           |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting L2/L3 traffic on Ixia.      |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_traffic                    | Stops L2/L3 traffic on Ixia device.            |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping L2/L3 traffic on Ixia.      |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | clear_statistics                | Clears L2/L3 traffic statistics on Ixia device.|
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           clearing protocol and traffic        |
    |                                 |           statistics on Ixia.                  |
    |                                 |           Default: 10 (seconds)                |
    |                                 |     * [O] clear_port_stats - flag to control   |
    |                                 |           execution of the command             |
    |                                 |           'clearPortsAndTrafficStats' as a part|
    |                                 |           of clear_statistics().               |
    |                                 |           Default: True                        |
    |                                 |     * [O] clear_protocol_stats - flag to       |
    |                                 |           control execution of the command     |
    |                                 |           'clearProtocolStats' as a part of    |
    |                                 |           of clear_statistics().               |
    |                                 |           Default: True                        |
    |---------------------------------+------------------------------------------------|
    | create_genie_statistics_view    | Creates a custom statistics view on IxNetwork  |
    |                                 | named "GENIE" with the required data fields    |
    |                                 | needed for processors.                         |
    |                                 | Arguments:                                     |
    |                                 |     * [O] view_create_interval - time to wait  |
    |                                 |           after creating custom view before    |
    |                                 |           rechecking if it is populated and    |
    |                                 |           visible.                             |
    |                                 |           Default: 30 (seconds)                |
    |                                 |     * [O] view_create_iteration - max number of|
    |                                 |           iterations while checking if custom  |
    |                                 |           view is populated and visible.       |
    |                                 |           Default: 10.                         |
    |                                 |     * [O] enable_tracking - flag to control the|
    |                                 |           enabling of filter "Flow tracking"   |
    |                                 |           per traffic stream.                  |
    |                                 |           Default: True.                       |
    |                                 |     * [O] enable_port_pair - flag to control   |
    |                                 |           the enabling of filter               |
    |                                 |           "Src/Dest Port Pair" per traffic     |
    |                                 |           stream.                              |
    |                                 |           Default: True.                       |
    |                                 |     * [O] disable_tracking - disable enabling  |
    |                                 |           'Traffic Items' filter if not present|
    |                                 |           Default: False.                      |
    |                                 |     * [O] disable_port_pair - disable enabling |
    |                                 |           'Source/Dest Port Pair' filter if    |
    |                                 |           not present.                         |
    |                                 |           Default: False.                      |
    |---------------------------------+------------------------------------------------|
    | check_traffic_loss              | Checks all traffic streams for traffic loss.   |
    |                                 | For each traffic stream configured on Ixia:    |
    |                                 |   1. Verify traffic outage (in seconds) is less|
    |                                 |      than tolerance threshold value.           |
    |                                 |   2. Verify current loss % is less than        |
    |                                 |      tolerance threshold value.                |
    |                                 |   3. Verify difference between Tx Rate & Rx    |
    |                                 |      Rate is less than tolerance threshold.    |
    |                                 | Arguments:                                     |
    |                                 |     * [O] traffic_streams - list of specific   |
    |                                 |           traffic stream names to check traffic|
    |                                 |           loss for.                            |
    |                                 |           Default: None                        |
    |                                 |     * [O] max_outage - maximum outage expected |
    |                                 |           in packets/frames per second.        |
    |                                 |           Default: 120 (seconds)               |
    |                                 |     * [O] loss_tolerance - maximum traffic loss|
    |                                 |           expected in percentage %.            |
    |                                 |           Default: 15%.                        |
    |                                 |     * [O] rate_tolerance - maximum difference  |
    |                                 |           Tx Rate and Rx Rate expected.        |
    |                                 |           Default: 5 (packets per second)      |
    |                                 |     * [O] check_interval - wait time between   |
    |                                 |           traffic loss checks on Ixia.         |
    |                                 |           Default: 30 (seconds)                |
    |                                 |     * [O] check_iteration - max iterations for |
    |                                 |           traffic loss checks.                 |
    |                                 |           Default: 10.                         |
    |                                 |     * [O] outage_dict - user provided Python   |
    |                                 |           dictionary containing traffic stream |
    |                                 |           specific max_outage, loss_tolerance  |
    |                                 |           and rate_tolerance values for checks.|
    |                                 |           Default: None                        |
    |                                 |     * [O] clear_stats - flag to enable clearing|
    |                                 |           of all traffic statistics before     |
    |                                 |           checking for traffic loss/outage.    |
    |                                 |           Default: False                       |
    |                                 |     * [O] clear_stats_time - time to wait after|
    |                                 |           clearing all traffic statistics if   |
    |                                 |           enabled by user.                     |
    |                                 |           Default: 30 (seconds)                |
    |                                 |     * [O] pre_check_wait - time to wait before |
    |                                 |           checking for traffic loss/outage.    |
    |                                 |           Default: None                        |
    |                                 |     * [O] disable_tracking - disable enabling  |
    |                                 |           'Traffic Items' filter if not present|
    |                                 |           Default: False.                      |
    |                                 |     * [O] disable_port_pair - disable enabling |
    |                                 |           'Source/Dest Port Pair' filter if    |
    |                                 |           not present.                         |
    |                                 |           Default: False.                      |
    |---------------------------------+------------------------------------------------|
    | create_traffic_streams_table    | Creates and returns a table containing traffic |
    |                                 | statistics for all traffic items/streams that  |
    |                                 | are configured on traffic generator devicce.   |
    |                                 | Format of table is Python PrettyTable.         |
    |                                 | Arguments:                                     |
    |                                 |     * [O] set_golden - sets the traffic table  |
    |                                 |           created to be the "golden" profile   |
    |                                 |           for the current run.                 |
    |                                 |           Default: False                       |
    |                                 |     * [O] clear_stats - clears traffic stats   |
    |                                 |           before creating traffic table.       |
    |                                 |           Default: False                       |
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
    |                                 |           view is ready.                       |
    |                                 |           Default: 10.                         |
    |                                 |     * [O] disable_tracking - disable enabling  |
    |                                 |           'Traffic Items' filter if not present|
    |                                 |           Default: False.                      |
    |                                 |     * [O] disable_port_pair - disable enabling |
    |                                 |           'Source/Dest Port Pair' filter if    |
    |                                 |           not present.                         |
    |                                 |           Default: False.                      |
    |---------------------------------+------------------------------------------------|
    | compare_traffic_profile         | Compares values between two Ixia traffic table |
    |                                 | statistics created from custom IxNetwork view  |
    |                                 | Arguments:                                     |
    |                                 |     * [M] profile1 - 1st Ixia traffic profile  |
    |                                 |     * [M] profile2 - 2nd Ixia traffic profile  |
    |                                 |     * [O] loss_tolerance - maximum expected    |
    |                                 |           difference between loss % statistics |
    |                                 |           between both Ixia traffic profiles.  |
    |                                 |           Default: 5%                          |
    |                                 |     * [O] rate_tolerance - maximum expected    |
    |                                 |           difference of Tx Rate & Rx Rate      |
    |                                 |           between both Ixia traffic profiles.  |
    |                                 |           Default: 2 (packets per second)      |
    |----------------------------------------------------------------------------------|
    |                               Utils                                              |
    |----------------------------------------------------------------------------------|
    | save_statistics_snapshot_csv    | Save statistics views 'Flow Statistics' or     |
    |                                 | 'Traffic Item Statistics' snapshot as a CSV    |
    |                                 | Arguments:                                     |
    |                                 |     * [M] view_name - name of statistic view to|
    |                                 |           take CSV snapshot of. Can be only    |
    |                                 |           'Flow Statistics' or the             |
    |                                 |           'Traffic Item Statistics'            |
    |                                 |     * [M] csv_windows_path - Location to save  |
    |                                 |           the CSV snapshot file to on the      |
    |                                 |           IxNetwork client desktop.            |
    |                                 |     * [O] csv_file_name - File name to save    |
    |                                 |           the CSV snapshot file as.            |
    |                                 |           Default: Ixia_Statistics.csv         |
    |---------------------------------+------------------------------------------------|
    | get_all_statistics_views        | Returns all the statistics views/tabs that are |
    |                                 | currently present on IxNetwork client.         |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    |                               Traffic                                            |
    |----------------------------------------------------------------------------------|
    | get_traffic_attribute           | Returns the value of the specified traffic     |
    |                                 | configuration attribute.                       |
    |                                 | Arguments:                                     |
    |                                 |     * [M] attribute - traffic configuration    |
    |                                 |           attribute to retrieve value of.      |
    |                                 |           Sample attributes are:               |
    |                                 |           - 'state'                            |
    |                                 |           - 'isApplicationTrafficRunning'      |
    |                                 |           - 'isTrafficRunning'                 |
    |---------------------------------+------------------------------------------------|
    |get_traffic_items_from_genie_view| Returns list of all traffic items from within  |
    |                                 | the custome created IxNetwork view "GENIE"     |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | enable_flow_tracking_filter     | Enable specific flow tracking filter for all   |
    |                                 | the configured traffic streams.                |
    |                                 | Arguments:                                     |
    |                                 |     * [M] tracking_filter - name of the Ixia   |
    |                                 |           tracking filter to enable for the    |
    |                                 |           configured traffic streams.          |
    |---------------------------------+------------------------------------------------|
    | get_golden_profile              | Returns the "golden" traffic profile in Python |
    |                                 | PrettyTable format. If not set, returns empty  |
    |                                 | table.                                         |
    |----------------------------------------------------------------------------------|
    |                             Virtual Ports                                        |
    |----------------------------------------------------------------------------------|
    | assign_ixia_ports               | Assign physical Ixia ports from the loaded     |
    |                                 | configuration to corresponding virtual ports.  |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - Time to wait after       |
    |                                 |           assigning physical Ixia ports to the |
    |                                 |           corresponding virtual ports.         |
    |---------------------------------+------------------------------------------------|
    | set_ixia_virtual_ports          | Set virtual Ixia ports to the IxiaNative object|
    |                                 | for the given configuration.                   |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | get_ixia_virtual_port           | Return virtual Ixia port object from port_name |
    |                                 | Arguments:                                     |
    |                                 |     * [M] port_name - port on which packet     |
    |                                 |           capture session was performed.       |
    |---------------------------------+------------------------------------------------|
    | get_ixia_virtual_port_attribute | Returns an attibute for virtual Ixia port      |
    |                                 | Arguments:                                     |
    |                                 |     * [M] vport - virtual Ixia port for config |
    |                                 |     * [M] attribute - attribute of the virtual |
    |                                 |           to return to the caller.             |
    |---------------------------------+------------------------------------------------|
    |                              Packet Capture (PCAP)                               |
    |----------------------------------------------------------------------------------|
    | get_ixia_virtual_port_capture   | Get virtual port object for given port to use  |
    |                                 | in enabling packet capture.                    |
    |                                 | Arguments:                                     |
    |                                 |     * [M] port_name - port on which packet     |
    |                                 |           capture will be enabled.             |
    |----------------------------------------------------------------------------------|
    | enable_data_packet_capture      | Enable data packet capture on ports specified. |
    |                                 | Arguments:                                     |
    |                                 |     * [M] ports - list of ports to enable data |
    |                                 |           packet capture on.                   |
    |---------------------------------+------------------------------------------------|
    | disable_data_packet_capture     | Disable data packet capture on ports specified.|
    |                                 | Arguments:                                     |
    |                                 |     * [M] ports - list of ports to disable data|
    |                                 |           packet capture on.                   |
    |---------------------------------+------------------------------------------------|
    | enable_control_packet_capture   | Enable control packet capture on ports.        |
    |                                 | Arguments:                                     |
    |                                 |     * [M] ports - list of ports to enable      |
    |                                 |           control packet capture on.           |
    |---------------------------------+------------------------------------------------|
    | disable_control_packet_capture  | Disable control packet capture on ports.       |
    |                                 | Arguments:                                     |
    |                                 |     * [M] ports - list of ports to disable     |
    |                                 |           control packet capture on.           |
    |---------------------------------+------------------------------------------------|
    | start_packet_capture            | Starts packet capture (PCAP) on enabled ports. |
    |                                 | Arguments:                                     |
    |                                 |     * [O] capture_time - Time to wait while    |
    |                                 |           packet capture is occurring.         |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_packet_capture             | Stops packet capture (PCAP) on enabled ports.  |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
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
    | export_packet_capture_file      | Export packet capture file to runtime logs as  |
    |                                 | the given filename and return file path of the |
    |                                 | copied file to caller.                         |
    |                                 | Arguments:                                     |
    |                                 |     * [M] src_file - location of packet capture|
    |                                 |           on host IxNetwork API server.        |
    |                                 |     * [O] dest_file - filename to copy the     |
    |                                 |           packet capture file outside the      |
    |                                 |           IxNetwork API server to runtime logs.|
    |                                 |           Default: 'ixia.pcap'                 |
    |----------------------------------------------------------------------------------|
    |                              Traffic Item (Stream)                               |
    |----------------------------------------------------------------------------------|
    | get_traffic_stream_names        | Returns a list of all traffic stream names     |
    |                                 | present in current Ixia configuration.         |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    | get_traffic_stream_objects      | Returns a list of all traffic stream IxNetwork |
    |                                 | objects present in current Ixia configuration. |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    | find_traffic_stream_object      | Returns the corresponding traffic stream object|
    |                                 | for the given traffic stream name.             |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to find the corresponding ::ixNet::  |
    |                                 |           traffic stream object.               |
    |---------------------------------+------------------------------------------------|
    | get_traffic_stream_attribute    | Returns the specified attribute of the given   |
    |                                 | traffic stream.                                |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           for which to get specified attribute.|
    |                                 |     * [M] attribute - attribute to return of   |
    |                                 |           given traffic stream.                |
    |----------------------------------------------------------------------------------|
    | start_traffic_stream            | Start specific traffic item/stream name on Ixia|
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream/item |
    |                                 |           to start stateless traffic on.       |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting traffic stream to ensure Tx |
    |                                 |           Rate is greater than 0 pps.          |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_traffic_stream             | Stop specific traffic item/stream name on Ixia |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream      |
    |                                 |           to stop stateless traffic on.        |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping traffic stream to ensure Tx |
    |                                 |           Rate is 0 pps.                       |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | generate_traffic_streams        | Generates L2/L3 traffic for specified traffic  |
    |                                 | stream on Ixia.                                |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_streams - list of traffic    |
    |                                 |           streams to generate traffic for after|
    |                                 |           config has changed on Ixia.          |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           generating L2/L3 traffic for the     |
    |                                 |           given traffic stream.                |
    |                                 |           Default: 15 (seconds)                |
    |----------------------------------------------------------------------------------|
    |                             Traffic Item Statistics                              |
    |----------------------------------------------------------------------------------|
    |get_traffic_items_statistics_data| Get value of specified Traffic Items Statistics|
    |                                 | IxNetwork column data for the given traffic    |
    |                                 | stream.                                        |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - name of the traffic |
    |                                 |            stream to get data for.             |
    |                                 |     * [M] traffic_data_field - column name from|
    |                                 |           "Traffic Item Statistics" IxNetwork  |
    |                                 |           view to get the data of.             |
    |----------------------------------------------------------------------------------|
    |                              Flow Groups                                         |
    |----------------------------------------------------------------------------------|
    | get_flow_group_names            | 'Returns a list of names of all the flow groups|
    |                                 | present for the given traffic stream in current|
    |                                 | configuration.                                 |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream  - flow group parent  |
    |                                 |           traffic stream name.                 |
    |---------------------------------+------------------------------------------------|
    | get_flow_group_objects          | Returns a list of flow group objects for the   |
    |                                 | given traffic stream present in current        |
    |                                 | configuration.                                 |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream  - flow group parent  |
    |                                 |           traffic stream name.                 |
    |---------------------------------+------------------------------------------------|
    | find_flow_group_object          | Finds the corresponding flow group object when |
    |                                 | for the given the flow group name and traffic  |
    |                                 | stream name.                                   |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream  - flow group parent  |
    |                                 |           traffic stream name.                 |
    |                                 |     * [M] flow_group - flow group name to find |
    |                                 |           the corresponding ::ixNet:: object.  |
    |---------------------------------+------------------------------------------------|
    | start_flow_group                | Start traffic on given flow group of traffic   |
    |                                 | stream on Ixia.                                |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream  - flow group parent  |
    |                                 |           traffic stream name.                 |
    |                                 |     * [M] flow_group - flow group to start     |
    |                                 |           traffic on.                          |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting traffic on flow group.      |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_flow_group                 | Stop traffic on given flow group of traffic    |
    |                                 | stream on Ixia.                                |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream  - flow group parent  |
    |                                 |           traffic stream name.                 |
    |                                 |     * [M] flow_group - flow group to start     |
    |                                 |           traffic on.                          |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping traffic on flow group.      |
    |                                 |           Default: 15 (seconds)                |
    |----------------------------------------------------------------------------------|
    |                               Quick Flow Groups                                  |
    |----------------------------------------------------------------------------------|
    | get_quick_flow_group_names      | Returns a list of names of all the Quick Flow  |
    |                                 | Groups present in current configuration.       |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | get_quick_flow_group_objects    | Returns a list of all the Quick Flow Group     |
    |                                 | IxNetwork objects in current configuration.    |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | find_quick_flow_group_object    | Finds the Quick Flow Group object when given   |
    |                                 | the Quick Flow Group name.                     |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quick_flow_group - quick flow qroup  |
    |                                 |           name to find the corresponding       |
    |                                 |           ::ixNet:: object.                    |
    |---------------------------------+------------------------------------------------|
    | get_quick_flow_group_attribute  | Returns the specified attribute for the given  |
    |                                 | Quick Flow Group.                              |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quick_flow_group - quick flow group  |
    |                                 |           name to get attributes of.           |
    |                                 |     * [M] attribute - attribute of the quick   |
    |                                 |           flow group to retrieve.              |
    |---------------------------------+------------------------------------------------|
    | start_quick_flow_group          | Start traffic for given Quick Flow Group on    |
    |                                 | on Ixia.                                       |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quick_flow_group - quick flow group  |
    |                                 |           to start traffic on.                 |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting traffic on quick flow group.|
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_quick_flow_group           | Stop traffic for given Quick Flow Group on     |
    |                                 | on Ixia.                                       |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quick_flow_group - quick flow group  |
    |                                 |           to stop traffic on.                  |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping traffic on quick flow group.|
    |                                 |           Default: 15 (seconds)                |
    |----------------------------------------------------------------------------------|
    |                       Flow Statistics Data                                       |
    |----------------------------------------------------------------------------------|
    | get_flow_statistics_data        | Get value of given field for the given traffic |
    |                                 | stream from the  "Flow Statistics" tab/view.   |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic stream - traffic stream to   |
    |                                 |           get the data of.                     |
    |                                 |     * [M] flow_data_filed - field/column under |
    |                                 |           "Flow Statistics" view to get the    |
    |                                 |           value of.                            |
    |---------------------------------+------------------------------------------------|
    | find_flow_statistics_page_obj   | Find "Flow Statistics" tab/view page object    |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    |save_flow_statistics_snapshot_csv| Save the data from all the rows/pages of Ixia  |
    |                                 | "Flow Statistics" view/tab as CSV snapshot file|
    |                                 | Arguments:                                     |
    |                                 |     * [M] csv_windows_path - location to save  |
    |                                 |           the CSV snapshot generated on Ixia   |
    |                                 |           windows API server.                  |
    |                                 |     * [M] csv_file_name - name of the CSV      |
    |                                 |           snapshot file to save data into.     |
    |---------------------------------+------------------------------------------------|
    | check_flow_groups_loss          | Checks traffic loss for all flow groups that   |
    |                                 | are configured on Ixia using data from the     |
    |                                 | 'Flow Statistics' tab/view.                    |
    |                                 | For each flow group configured on Ixia:        |
    |                                 |   1. Verify traffic outage (in seconds) is less|
    |                                 |      than tolerance threshold value.           |
    |                                 |   2. Verify current loss % is less than        |
    |                                 |      tolerance threshold value.                |
    |                                 |   3. Verify difference between Tx Rate & Rx    |
    |                                 |      Rate is less than tolerance threshold.    |
    |                                 | Arguments:                                     |
    |                                 |     * [O] traffic_streams - list of specific   |
    |                                 |           traffic stream names to check traffic|
    |                                 |           loss for.                            |
    |                                 |     * [O] max_outage - maximum outage expected |
    |                                 |           in packets/frames per second.        |
    |                                 |           Default: 120 (seconds)               |
    |                                 |     * [O] loss_tolerance - maximum traffic loss|
    |                                 |           expected in percentage %.            |
    |                                 |           Default: 15%.                        |
    |                                 |     * [O] rate_tolerance - maximum difference  |
    |                                 |           Tx Rate and Rx Rate expected.        |
    |                                 |           Default: 5 (packets per second)      |
    |                                 |     * [O] csv_windows_path - location to save  |
    |                                 |           the CSV snapshot generated on Ixia   |
    |                                 |           windows API server.                  |
    |                                 |     * [O] csv_file_name - name of the CSV      |
    |                                 |           snapshot file to save data into.     |
    |                                 |     * [O] verbose - enable/disable printing of |
    |                                 |           outage verified for each flow group  |
    |                                 |     * [O] remove_vlan - remove 'VLAN:VLAN-ID'  |
    |                                 |           check.
    |---------------------------------+------------------------------------------------|
    | get_flow_statistics_table       | Returns the last "Flow Statistics" table that  |
    |                                 | was created using CSV snapshot data.           |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    |                       Line / Packet / Layer2-bit Rate                            |
    |----------------------------------------------------------------------------------|
    | set_line_rate                   | Set the line rate for given traffic stream or  |
    |                                 | given flow group of a traffic stream on Ixia.  |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the line rate.             |
    |                                 |     * [M] rate - New value to set/configure the|
    |                                 |           line rate to.                        |
    |                                 |     * [O] flow_group - flow group of given     |
    |                                 |           traffic stream to set line rate for. |
    |                                 |           Default: Empty                       |
    |                                 |     * [O] stop_traffic_time - time to wait     |
    |                                 |           after stopping traffic for setting   |
    |                                 |           line rate for given traffic stream.  |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] generate_traffic_time - time to wait |
    |                                 |           after generating traffic for setting |
    |                                 |           line rate for given traffic stream.  |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           line rate for given traffic stream.  |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic on Ixia after       |
    |                                 |           setting the line rate.               |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           line rate for given traffic stream.  |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | set_packet_rate                 | Set the packet rate for given traffic stream or|
    |                                 | given flow group of a traffic stream on Ixia.  |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the packet rate.           |
    |                                 |     * [M] rate - New value to set/configure the|
    |                                 |           packet rate to.                      |
    |                                 |     * [O] flow_group - flow group of given     |
    |                                 |           traffic stream to set packet rate for|
    |                                 |           Default: Empty                       |
    |                                 |     * [O] stop_traffic_time - time to wait     |
    |                                 |           after stopping traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] generate_traffic_time - time to wait |
    |                                 |           after generating traffic for setting |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic on Ixia after       |
    |                                 |           setting the line rate.               |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | set_layer2_bit_rate             | Set the layer2 bit rate for given traffic      |
    |                                 | stream or given flow group of a traffic stream |
    |                                 | on Ixia.                                       |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the layer2 bit rate.       |
    |                                 |     * [M] rate - New value to set/configure the|
    |                                 |           layer2 bit rate to.                  |
    |                                 |     * [M] rate_units - For layer2 bit rate,    |
    |                                 |           specify the units to set the value.  |
    |                                 |           Valid Options: - bps                 |
    |                                 |                          - Kbps                |
    |                                 |                          - Mbps                |
    |                                 |                          - Bps                 |
    |                                 |                          - KBps                |
    |                                 |                          - MBps                |
    |                                 |     * [O] flow_group - flow group of given     |
    |                                 |           traffic stream to set layer2 bit rate|
    |                                 |           Default: Empty                       |
    |                                 |     * [O] stop_traffic_time - time to wait     |
    |                                 |           after stopping traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] generate_traffic_time - time to wait |
    |                                 |           after generating traffic for setting |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic on Ixia after       |
    |                                 |           setting the line rate.               |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | set_packet_size_fixed           | Set the packet size for given traffic stream   |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the packet size.           |
    |                                 |     * [M] packet_size - New value to set/config|
    |                                 |           the packet size to.                  |
    |                                 |     * [O] stop_traffic_time - time to wait     |
    |                                 |           after stopping traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] generate_traffic_time - time to wait |
    |                                 |           after generating traffic for setting |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic on Ixia after       |
    |                                 |           setting the line rate.               |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | get_line_rate                   | Returns the currently configured line rate for |
    |                                 | the traffic stream or flow group provided.     |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the line rate of.             |
    |                                 |     * [O] flow_group - flow group of given     |
    |                                 |           traffic stream to get line rate of.  |
    |                                 |           Default: Empty                       |
    |---------------------------------+------------------------------------------------|
    | get_packet_rate                 | Returns the currently configured packet rate   |
    |                                 | for the traffic stream or flow group provided. |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the packet rate of.           |
    |                                 |     * [O] flow_group - flow group of given     |
    |                                 |           traffic stream to get packet rate of.|
    |                                 |           Default: Empty                       |
    |---------------------------------+------------------------------------------------|
    | get_layer2_bit_rate             | Returns the currently configured layer2 bit    |
    |                                 | rate for the traffic stream or flow group      |
    |                                 | provided.                                      |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the layer2 bit rate of.       |
    |                                 |     * [O] flow_group - flow group of given     |
    |                                 |           traffic stream to get layer2 bit rate|
    |                                 |           Default: Empty                       |
    |---------------------------------+------------------------------------------------|
    | get_packet_size                 | Returns the currently configured packet size   |
    |                                 | for the traffic stream provided.               |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the packet size of.           |
    |----------------------------------------------------------------------------------|
    |                              QuickTest                                           |
    |----------------------------------------------------------------------------------|
    | find_quicktest_object           | Finds and returns the QuickTest object for the |
    |                                 | specified Quicktest using the name.            |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quicktest - Quicktest name to find   |
    |                                 |           the corresponding ::ixNet:: object   |
    |                                 |           Valid QuickTest name options:        |
    |                                 |             - rfc2544frameLoss                 |
    |                                 |             - rfc2544throughput                |
    |                                 |             - rfc2544back2back                 |
    |---------------------------------+------------------------------------------------|
    | get_quicktest_results_attribute | Returns the value of the specified Quicktest   |
    |                                 | results object attribute.                      |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quicktest - Quicktest name to find   |
    |                                 |           the corresponding ::ixNet:: object   |
    |                                 |     * [M] attribute - Quicktest results        |
    |                                 |           attribute to retrieve value of.      |
    |                                 |           Valid attributes are:                |
    |                                 |           - 'isRunning'                        |
    |                                 |           - 'status'                           |
    |                                 |           - 'progress'                         |
    |                                 |           - 'result'                           |
    |                                 |           - 'resultPath'                       |
    |                                 |           - 'startTime'                        |
    |                                 |           - 'duration'                         |
    |---------------------------------+------------------------------------------------|
    | load_quicktest_configuration    | Load QuickTest configuration file on Ixia.     |
    |                                 | Arguments:                                     |
    |                                 |     * [M] configuration - Absolute path to the |
    |                                 |           QuickTest configuration file to load |
    |                                 |           on Ixia.                             |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           loading Quicktest configuration on   |
    |                                 |           Ixia.                                |
    |                                 |           Default: 30 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | execute_quicktest               | Execute specific RFC QuickTest after loading   |
    |                                 | configuration file for it.                     |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quicktest - Quicktest name to find   |
    |                                 |           the corresponding ::ixNet:: object   |
    |                                 |     * [O] apply_wait - time to wait after      |
    |                                 |           applying quicktest configuration file|
    |                                 |           Default: 60 (seconds)                |
    |                                 |     * [O] exec_wait - maximum time during which|
    |                                 |           Quicktest should have completed its  |
    |                                 |           execution.                           |
    |                                 |           Default: 1800 (seconds)              |
    |                                 |     * [O] exec_interval - time to wait while   |
    |                                 |           polling to check if Quicktest        |
    |                                 |           execution has completed.             |
    |                                 |           Default: 300 (seconds)               |
    |                                 |     * [O] save_location - default location to  |
    |                                 |           Quicktest PDF report to on Ixia      |
    |                                 |           windows API server.                  |
    |                                 |           Default: C:\\Users\\                 |
    |---------------------------------+------------------------------------------------|
    |generate_export_quicktest_report | Generate QuickTest PDF report and export the   |
    |                                 | file to directory and filename specified.      |
    |                                 | Arguments:                                     |
    |                                 |     * [M] quicktest - Quicktest name to find   |
    |                                 |           the corresponding ::ixNet:: object   |
    |                                 |     * [O] report_wait - max time to wait for   |
    |                                 |           PDF report generation to complete.   |
    |                                 |           Default: 300 (seconds)               |
    |                                 |     * [O] report_interval - time to wait while |
    |                                 |           polling to check if PDF report has   |
    |                                 |           been generated.                      |
    |                                 |           Default: 60 (seconds)                |
    |                                 |     * [O] export - enable/disable exporting the|
    |                                 |           PDF results report generated after   |
    |                                 |           executing Quicktest.                 |
    |                                 |           Default: True                        |
    |                                 |     * [O] dest_dir - directory to copy the PDF |
    |                                 |           results report to.                   |
    |                                 |           Default: Genie Harness runtime dir   |
    |                                 |     * [O] dest_file - filename to copy the PDF |
    |                                 |           results report as.                   |
    |                                 |           Default: TestReport.pdf              |
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


Genie Harness Traffic Arguments
-------------------------------

User's can specify arguments to control the ``Genie`` harness subsections via:

    1. Via gRun in the job file as shown in the example below:

    .. code-block:: python

        gRun(config_datafile=os.path.join(test_path, 'config_datafile.yaml'),
             tgn_disable_start_protocols=True,
             tgn_traffic_loss_tolerance=15.0)


    2. Via command line arguments as shown in the example below:

    .. code-block:: bash

        pyats run job job.py --testbed-file <testbed yaml> \
                             --tgn-disable-start-protocols True \
                             --tgn-traffic-loss-tolerance 15.0

    .. code-block:: bash

        easypy job.py -testbed_file <testbed yaml> \
                      -tgn_disable_start_protocols True \
                      -tgn_traffic_loss_tolerance 15.0

.. note::
    Please note that when specifying traffic generator arguments in the job
    file to gRun, the user must use argument names with underscores(_).
    Example: "tgn_disable_start_traffic"

    When specifying traffic generator arguments via command line, the user must
    use argument names with double dash and hyphens (-) when using
    ``pyats run job`` or with single dash and underscores (_) when using
    ``easypy`` to kick off a run.

    Example: "--tgn-disable-start-traffic" (payts run job) or "-tgn_disable_start_traffic" (easypy)


The table below is a list of arguments that can be configured by the user to control
traffic generator subsections in ``Genie`` harness.

.. code-block:: text

    +--------------------------------------------------------------------------+
    | Genie Harness Traffic Generator Arguments                                |
    +==========================================================================+
    | Argument                         | Description                           |
    |----------------------------------+---------------------------------------|
    | tgn-port-list                    | Modify the Ixia ports list to connect |
    | tgn_port_list                    | to, from the existing ixia_port_list  |
    |                                  | Default: []                           |
    |----------------------------------+---------------------------------------|
    | tgn-disable-load-configuration   | Ddisable loading static configuration |
    | tgn_disable_load_configuration   | file on Ixia in 'initialize_traffic'  |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-load-configuration-time      | Time to wait after loading config     |
    | tgn_load_configuration_time      | on Ixia during 'initialize_traffic'   |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-assign-ports         | Disable assigning physical ports to   |
    | tgn_disable_assign_ports         | virtual Ixia ports in                 |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-assign-ports-time            | Time to wait after assigning physical |
    | tgn_assign_ports_time            | ports to virtual ports on Ixia in     |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-start-protocols      | Ddisable starting protocols on Ixia   |
    | tgn_disable_start_protocols      | in 'initialize_traffic'               |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-protocols-convergence-time   | Time to wait for all traffic streams  |
    | tgn_protocols_convergence_time   | converge to steady state in           |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 120 (seconds)                |
    |----------------------------------+---------------------------------------|
    | tgn-stop-protocols-time          | Time to wait after stopping protocols |
    | tgn_stop_protocols_time          | on Ixia during 'stop_traffic'         |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-regenerate-traffic   | Disable regenerating of traffic for   |
    | tgn_disable_regenerate_traffic   | all configured traffic streams in     |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: True                         |
    |----------------------------------+---------------------------------------|
    | tgn-regenerate-traffic-time      | Time to wait after regenerating       |
    | tgn_regenerate_traffic_time      | traffic for all configured traffic    |
    |                                  | streams in 'initialize_traffic'       |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-apply-traffic        | Disable applying L2/L3 traffic on     |
    | tgn_disable_apply_traffic        | Ixia in 'initialize_traffic'          |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-apply-traffic-time           | Time to wait after applying L2/L3     |
    | tgn_apply_traffic_time           | traffic in 'initialize_traffic'       |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-send-arp             | Disable send ARP to interfaces from   |
    | tgn_disable_send_arp             | Ixia in 'initialize_traffic'          |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-arp-wait-time                | Time to wait after sending ARP from   |
    | tgn_arp_wait_time                | Ixia in 'initialize_traffic'          |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-send-ns              | Disable send NS to interfaces on Ixia |
    | tgn_disable_send_ns              | in 'initialize_traffic'               |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-ns-wait-time                 | Time to wait after sending NS packet  |
    | tgn_ns_wait_time                 | from Ixia in 'initialize_traffic'     |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-start-traffic        | Disable starting L2/L3 traffic on     |
    | tgn_disable_start_traffic        | Ixia in 'initialize_traffic'          |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-steady-state-convergence-time| Time to wait for traffic streams to   |
    | tgn_steady_state_convergence_time| converge to steady state after start  |
    |                                  | traffic in 'initialize_traffic'       |
    |                                  | Default: 15 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-stop-traffic-time            | Time to wait after stopping traffic   |
    | tgn_stop_traffic_time            | streams in 'stop_traffic'             |
    |                                  | Default: 15 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-remove-configuration         | Remove configuration after stopping   |
    | tgn_remove_configuration         | traffic streams in 'stop_traffic'     |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-remove-configuration-time    | Time to wait after removing all Ixia  |
    | tgn_remove_configuration_time    | configuration in 'stop_traffic'       |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-clear-statistics     | Disable clearing of all protocol and  |
    | tgn_disable_clear_statistics     | traffic statistics on Ixia in         |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-clear-stats-time             | Time to wait after clearing protocol  |
    | tgn_clear_stats_time             | and traffic statistics on Ixia in     |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-disable-check-traffic-loss   | Disable checking of frames loss       |
    | tgn_disable_check_traffic_loss   | and traffic loss for all configured   |
    |                                  | traffic streams after starting L2/L3  |
    |                                  | traffic on Ixia in'initialize_traffic'|
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-traffic-outage-tolerance     | Maximum traffic outage expected after |
    | tgn_traffic_outage_tolerance     | starting traffic on Ixia in           |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 120 (seconds)                |
    |----------------------------------+---------------------------------------|
    | tgn-traffic-loss-tolerance       | Maximum traffic loss % accepted after |
    | tgn_traffic_loss_tolerance       | starting traffic on Ixia in           |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: 15%                          |
    |----------------------------------+---------------------------------------|
    | tgn-traffic-rate-tolerance       | Maximum difference between Tx Rate and|
    | tgn_traffic_rate_tolerance       | Rx Rate expected after starting       |
    |                                  | traffic in 'initialize_traffic'       |
    |                                  | Default: 5 (packets per second)       |
    |----------------------------------+---------------------------------------|
    | tgn-check-traffic-streams        | User provided list of traffic streams |
    | tgn_check_traffic_streams        | to check traffic loss for. All other  |
    |                                  | traffic stream will be ignored for    |
    |                                  | performing traffic loss checks.       |
    |                                  | Default: None (All streams checked)   |
    |----------------------------------+---------------------------------------|
    | tgn-traffic-streams-data         | User provided YAML file containing the|
    | tgn_traffic_streams_data         | maximum expected traffic outage, loss |
    |                                  | and frame rate tolerance for each     |
    |                                  | traffic item configured. Genie will   |
    |                                  | check if specific traffic streams have|
    |                                  | been provided in this YAML and use the|
    |                                  | values provided here. If a configured |
    |                                  | stream is not in the YAML, Genie will |
    |                                  | use the values provided in:           |
    |                                  | 1. tgn-traffic-outage-tolerance       |
    |                                  | 2. tgn-traffic-loss-tolerance         |
    |                                  | 3. tgn-traffic-rate-tolerance         |
    |                                  | to check for traffic loss in          |
    |                                  | 'initialize_traffic'                  |
    |                                  | Default: None                         |
    |----------------------------------+---------------------------------------|
    | tgn-stabilization-interval       | Time to wait between re-checking all  |
    | tgn_stabilization_interval       | configured traffic streams on Ixia for|
    |                                  | traffic loss in 'initialize_traffic'  |
    |                                  | Default: 60 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-stabilization-iteration      | Number of attempts to re-check all the|
    | tgn_stabilization_iteration      | configured traffic streams on Ixia for|
    |                                  | traffic loss in 'initialize_traffic'  |
    |                                  | Default: 10 attempts                  |
    |----------------------------------+---------------------------------------|
    | tgn-golden-profile               | Full path to the text file containing |
    | tgn_golden_profile               | previously verified and saved traffic |
    |                                  | profile to compare it against in      |
    |                                  | 'profile_traffic'                     |
    |                                  | Default: None                         |
    |----------------------------------+---------------------------------------|
    | tgn-disable-profile-clear-stats  | Disable clearing of traffic statistics|
    | tgn_disable_profile_clear_stats  | before creating a table or profile of |
    |                                  | traffic statistics for the currently  |
    |                                  | executing job in 'profile_traffic'    |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-view-create-interval         | Time to wait between re-checking if   |
    | tgn_view_create_interval         | custom traffic items view "GENIE" is  |
    |                                  | ready in 'profile_traffic'            |
    |                                  | Default: 30 (seconds)                 |
    |----------------------------------+---------------------------------------|
    | tgn-view-create-iteration        | Number of attempts to re-check if the |
    | tgn_view_create_iteration        | custom traffic items view "GENIE" is  |
    |                                  | ready in 'profile_traffic'            |
    |                                  | Default: 10 attempts                  |
    |----------------------------------+---------------------------------------|
    | tgn-disable-tracking-filter      | Disable adding tracking filter        |
    | tgn_disable_tracking_filter      | "Traffic Items" to traffic stream     |
    |                                  | configuration while building "GENIE"  |
    |                                  | custom view in 'profile_traffic'      |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    | tgn-disable-port-pair-filter     | Disable adding tracking filter        |
    | tgn_disable_port_pair_filter     | "Source/Dest Port Pair" to traffic    |
    |                                  | streamconfiguration while building    |
    |                                  | "GENIE" view in 'profile_traffic'     |
    |                                  | Default: False                        |
    |----------------------------------+---------------------------------------|
    |tgn-profile-traffic-loss-tolerance| Maximum acceptable difference between |
    |tgn_profile_traffic_loss_tolerance| two Genie traffic profile snapshots   |
    |                                  | for loss % column in 'profile_traffic'|
    |                                  | Default: 2%                           |
    |----------------------------------+---------------------------------------|
    | tgn-profile-rate-loss-tolerance  | Maximum acceptable difference between |
    | tgn_profile_rate_loss_tolerance  | two Genie traffic profile snapshots   |
    |                                  | for Tx/Rx Rate in 'profile_traffic'   |
    |                                  | Default: 2 (packets per second)       |
    |----------------------------------+---------------------------------------|
    | tgn-logfile                      | Logfile to save all Ixia output       |
    | tgn_logfile                      | Default: 'tgn.log'                    |
    +==========================================================================+


.. note::
    Please note the following arguments are now deprecated and replaced as shown
    below. Default values can be found in the table above

.. code-block:: text

    +------------------------------------------------------------------+
    | Genie Harness Traffic Deprecated Arguments                       |
    +==================================================================+
    | Old Argument                  | New Argument                     |
    |-------------------------------+----------------------------------|
    | tgn-load-configuration        | tgn-disable-load-configuration   |
    | tgn-start-protocols           | tgn-disable-start-protocols      |
    | tgn-apply-traffic             | tgn-disable-apply-traffic        |
    | tgn-send-arp                  | tgn-disable-send-arp             |
    | tgn-send-ns                   | tgn-disable-send-ns              |
    | tgn-start-traffic             | tgn-disable-start-traffic        |
    | tgn-clear-statistics          | tgn-disable-clear-statistics     |
    | tgn-check-traffic-loss        | tgn-disable-check-traffic-loss   |
    | tgn-profile-clear-stats       | tgn-disable-profile-clear-stats  |
    | tgn-view-enable-tracking      | tgn-disable-tracking-filter      |
    | tgn-view-enable-port-pair     | tgn-disable-port-pair-filter     |
    +==================================================================+


Genie Harness Traffic Subsections
---------------------------------

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


common_setup: initialize_traffic
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This subsection packages the various steps associated with Ixia setup such as
connectiong and loading static configuration, enabling protocols, starting
traffic, etc into one runnable subsection. 

It performs the following steps in order:

    1. Connect to Ixia
    2. Load static configuration and assign physical ports to Ixia virtual ports
    3. Start all protocols
    4. Regenerate traffic streams
    5. Apply L2/L3 traffic configuration
    6. Send ARP, NS packet to all interfaces from Ixia
    7. Start L2/L3 traffic
    8. Clear traffic statistics after streams have converged to steady state
    9. Create custom traffic statistics view on Ixia named "Genie"
    10. Check traffic loss % and frames loss across all configured traffic streams


Step1: Connect to Ixia
"""""""""""""""""""""""

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


Step2: Load static configuration and assign physical ports to Ixia virtual ports
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-load-configuration`.

``Genie`` can load a static configuration file onto the Ixia `device` that has
been specified in the `configuration_datafile` as shown below:

.. code-block:: yaml

    devices:
      IXIA:
        1:
          config: /path/to/ixia_bgp_multicast.ixncfg

It waits for `tgn-load-configuration-time` seconds for traffic to be loaded onto
Ixia.

Following loading configuration, ``Genie`` harness will proceed to assign physical
Ixia ports specified in the testbed YAML to virtual Ixia ports. This step can be 
disabled by setting argument `tgn-disable-assign-ports`. 
It waits for `tgn-assign-ports-time` seconds for all ports to be up (green).


Step3: Start all protocols
"""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-start-protocols`.

If this flag is enabled, ``Genie`` harness will start all protocols on the Ixia
device and wait for `tgn-protocols-convergence-time` seconds for all traffic
streams to converge to steady state.


Step4: Regenerate traffic streams
""""""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-regenerate-traffic`.

If this flag is enabled, ``Genie`` harness will regenerate traffic for all the
configured traffic items on the traffic generator device and then wait for
`tgn-regenerate-traffic-time` seconds.


Step5: Apply L2/L3 traffic
"""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-apply-traffic`.

If this flag is enabled, ``Genie`` harness will apply L2/L3 traffic on the Ixia
device and wait for `tgn-apply-traffic-time` seconds after applying traffic.


Step6: Send ARP, NS from Ixia
""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling arguments:

* `tgn-disable-send-arp` - send ARP to all interfaces from Ixia
* `tgn-disable-send-ns` - send NS to all interfaces from Ixia

If these flags are enabled, ``Genie`` harness will send ARP and NS to all
interfaces from Ixia. It will wait for `tgn-arp-wait-time` seconds after sending
ARP to all interfaces from Ixia and wait for `tgn-ns-wait-time` seconds after
sending NS packets to all interfaces from Ixia.


Step7: Start L2/L3 traffic
"""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-start-traffic`.

If this flag is enabled, ``Genie`` harness will start L2/L3 traffic on the Ixia
device and wait for `tgn-steady-state-convergence-time` seconds after starting
traffic for all traffic streams to converge to steady state.


Step8: Clear traffic statistics
""""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-clear-statistics`.

If this flag is enabled, ``Genie`` harness will clear all protocol, traffic
statistics on the Ixia device and wait for `tgn-clear-stats-time` seconds after
clearing traffic statistics for traffic collection to resume.


Step9: Create custom traffic statistics view on Ixia named "Genie"
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

``Genie`` harness will create a custom traffic items view named "GENIE" that
contains specific traffic statistics to be used for calculating traffic outages.
``Genie`` will attempt to check if the view is ready `tgn-view-create-iteration`
times, while waiting for `tgn-view-create-interval` seconds between each iteration.


Step10: Check for traffic loss
"""""""""""""""""""""""""""""""

This section can be controlled by enabling/disabling argument: `tgn-disable-check-traffic-loss`.

If this flag is enabled, ``Genie`` harness will verify that all configured
traffic streams have traffic outage, traffic loss and frames rate loss within the
expected user provided thresholds.

This section performs the following:

    1. Verify that the traffic outage (calculated by Frames Delta/Tx Rate) is
       less than the user provided threshold of ``tgn-traffic-outage-tolerance``
    2. Verify that the traffic loss is less than the user provided threshold of
       ``tgn-traffic-loss-tolerance``
    3. Verify that the difference between the Tx Frames Rate and Rx Frames rate
       is less than the user provided threshold of ``tgn-rate-loss-tolerance``

.. note::
    The threshold values provided above are used to verify all traffic streams
    configured on the traffic generator device. 

If the the threshold values for max_outage, loss_tolerance and rate_tolerance
are different *per stream*, the user can create a YAML file containing stream
specific threshold valuess. This YAML file can then be provided to the
common_setup via the argument ``tgn-traffic-streams-data``.

The following is an example of the traffic items YAML a user can provide:

.. code-block:: yaml

    traffic_streams:
        ospf:
            max_outage: 180
            loss_tolerance: 30
            rate_tolerance: 5
        ospfv3:
            max_outage: 120
            loss_tolerance: 20
            rate_tolerance: 2
        BSR N95_1 - N93_3:
            max_outage: 180
            loss_tolerance: 20
            rate_tolerance: 10
        MC Core to Access 4 (Agg3):
            max_outage: 1000
            loss_tolerance: 100
            rate_tolerance: 100

.. note::
    It is mandatory to label the top-level key as 'traffic_streams'

In the event that any of the above checks fail for a traffic item/stream due 
to the outage/loss being more than the acceptable threshold, ``Genie`` harness 
will re-check the streams every `tgn-stabilization-interval` seconds upto a
maximum of `tgn-stabilization-iteration` attempts for all the traffic streams to 
stabilize to steady state; i.e. for traffic outage/loss to become lower than the
acceptable tolerance limit. 

If traffic streams do not stabilize, ``Genie`` harness marks the traffic loss
check section as failed.


common_setup: profile_traffic
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This subsection packages all the steps associated with "profiling" traffic
streams configured on Ixia.

It creates a snapshot/profile of all configured traffic streams and then copies 
this profile to the runtime logs as the "golden_traffic_profile" for the
current job/run. 

It also saves this snapshot/profile as the "golden" traffic profile for the
current ``Genie`` run. This snapshot profile will then be used to compare traffic
profiles generated after trigger execution to ensure that the trigger did not
impact configured traffic streams. For more details on this please refer to the
processor: compare_traffic_profile section.

This profile can also be saved and reused as a reference for comparison of
subsequent runs of ``profile_traffic`` subsection.

The user can pass in a ``golden`` traffic profile via the ``tgn-golden-profile``
argument to enable comparison of the current profile against the previously
established/verified/golden traffic profile snapshot.

This subsection performs the following:

    1. Connect to Ixia
    2. Create a snapshot profile of traffic streams configured on Ixia
    3. Copy the snapshot profile as "golden_traffic_profile" to Genie runtime logs
    4. (Optional) If the user provided a ``tgn-golden-profile``:
        a. Verify that the difference for Loss % between the current traffic
           profile and golden traffic profile is less than user provided
           threshold of ``tgn-profile-traffic-loss-tolerance``
        b. Verify that the difference for Tx Frames Rate between the current
           traffic profile and golden traffic profile is less than user provided
           threshold of ``tgn-profile-rate-loss-tolerance``
        c. Verify that the difference for Rx Frames Rate between the current
           traffic profile and golden traffic profile is less than user provided
           threshold of ``tgn-profile-rate-loss-tolerance`` 

To enable/disable execution of this subsection, simply add or remove the
'profile_traffic' subsection from the execution order of the 'setup' in the
`subsection_datafile` YAML.


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

.. code-block:: yaml

    global_processors:
      pre:
        clear_traffic_statistics:
          method: genie.harness.libs.prepostprocessor.clear_traffic_statistics
      post:
        check_traffic_loss:
          method: genie.harness.libs.prepostprocessor.check_traffic_loss
        compare_traffic_profile:
          method: genie.harness.libs.prepostprocessor.compare_traffic_profile

To disable *all* traffic related processors for a given trigger, users can
specify argument 'check_traffic: False' for the trigger in the trigger datafile
as shown below:

.. code-block:: yaml

    TriggerClearBgp:
      groups: ['bgp']
      check_traffic: False <--- will disable all global traffic processor
      devices: ['uut']


To disable globally enabled 'clear_traffic_statistics' processor for a given
trigger, users can specify argument 'clear_traffic_statistics: False' for the
trigger in the trigger datafile as shown below:

.. code-block:: yaml

    TriggerClearBgp:
      groups: ['bgp']
      clear_traffic_statistics: False <--- will disable only clear_traffic_statistics processor
      devices: ['uut']


To disable globally enabled 'check_traffic_loss' processor for a given
trigger, users can specify argument 'check_traffic_loss: False' for the
trigger in the trigger datafile as shown below:

.. code-block:: yaml

    TriggerClearBgp:
      groups: ['bgp']
      check_traffic_loss: False <--- will disable only check_traffic_loss processor
      devices: ['uut']


To disable globally enabled 'compare_traffic_profile' processor for a given
trigger, users can specify argument 'compare_traffic_profile: False' for the
trigger in the trigger datafile as shown below:

.. code-block:: yaml

    TriggerClearBgp:
      groups: ['bgp']
      compare_traffic_profile: False <--- will disable only compare_traffic_profile processor
      devices: ['uut']


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

`check_traffic_loss` is a ``Genie`` post-trigger processor. 

It performs the following steps:

    1. Verify that the traffic outage (calculated by Frames Delta/Tx Rate) is
       less than the user provided threshold of ``max_outage``
    2. Verify that the traffic loss is less than the user provided threshold of
       ``loss_tolerance``
    3. Verify that the difference between the Tx Frames Rate and Rx Frames rate
       is less than the user provided threshold of ``rate_tolerance``

If a configured traffic stream reports traffic loss that is not within the 
specified tolerance limit after the prescribed number of ``check_iterations``,
executed at ``check_interval`` seconds, ``Genie`` marks the trigger as "failed".

User's can define processor `check_traffic_loss` in the `trigger_datafile`
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
                max_outage: 120
                loss_tolerance: 15
                rate_tolerance: 5
                stream_settings: /ws/ellewoods-sjc/genie/ixia.yaml
                check_interval: 60
                check_iteration: 10
                clear_stats: True
                clear_stats_time: 30
                pre_check_wait: 60

The `check_traffic_loss` post-trigger processor has the following arguments:

1. [Optional] max_outage: Maximum packet/frames loss permitted. Default: 120 seconds
2. [Optional] loss_tolerance: Maximum loss % permitted. Default: 15%.
3. [Optional] rate_tolerance: Maximum loss % permitted. Default: 15%.
4. [Optional] check_interval: Wait time to re-check traffic/frames loss is within tolerance specified before failing processor. Default: 30 seconds.
5. [Optional] check_iteration: Maximum attempts to verify traffic/frames loss is within tolerance specified before failing processor. Default: 10 attempts.
6. [Optional] stream_settings: User provided YAML file containing per stream data for max_outage, loss_tolerance, rate_tolerance
7. [Optional] clear_stats: Enable/disable clearing of statistics before checking traffic loss/outage. Default: False
8. [Optional] clear_stats_time: Wait time after clearing statistics. Default: 30 seconds.
9. [Optional] pre_check_wait: Wait time before (clearing stats) and performing checks for traffic loss/outage. Default: None

The parameters above can also be set at both the local processor and global
processor level with the exception of argument 'stream_settings', which can only
be set at the trigger level.

.. note::
    The threshold values provided above are used to verify all traffic streams
    configured on the traffic generator device.

If the the threshold values for max_outage, loss_tolerance and rate_tolerance
are different *per stream*, the user can create a YAML file containing stream
specific threshold valuess. This YAML file can then be provided to the
processor via the argument ``stream_settings``.

The following is an example of the traffic items YAML a user can provide:

.. code-block:: yaml

    traffic_streams:
        ospf:
            max_outage: 180
            loss_tolerance: 30
            rate_tolerance: 5
        ospfv3:
            max_outage: 120
            loss_tolerance: 20
            rate_tolerance: 2
        BSR N95_1 - N93_3:
            max_outage: 180
            loss_tolerance: 20
            rate_tolerance: 10
        MC Core to Access 4 (Agg3):
            max_outage: 1000
            loss_tolerance: 100
            rate_tolerance: 100

.. note::
    It is mandatory to label the top-level key as 'traffic_streams'


processor: compare_traffic_profile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`compare_traffic_profile` is a ``Genie`` post-trigger processor. 

It performs the following steps:

1. Create a snapshot profile of traffic streams configured on Ixia
2. Copy the snapshot profile as "TriggerName_traffic_profile" to Genie runtime logs
3. (Optional) If the user provided a ``section_profile``:
    a. Verify that the difference for Loss % between the current traffic
       profile and section traffic profile is less than user provided
       threshold of ``loss_tolerance``
    b. Verify that the difference for Tx Frames Rate between the current
       traffic profile and section traffic profile is less than user provided
       threshold of ``rate_tolerance``
    c. Verify that the difference for Rx Frames Rate between the current
       traffic profile and section traffic profile is less than user provided
       threshold of ``rate_tolerance``
4. If the user does not provide ``section_profile`` for the given Trigger
    a. Verify that the difference for Loss % between the current traffic
       profile and common_setup profile_traffic created golden traffic profile 
       is less than user provided threshold of ``loss_tolerance``
    b. Verify that the difference for Tx Frames Rate between the current
       traffic profile and and common_setup profile_traffic created golden 
       traffic profile  is less than user provided threshold of ``rate_tolerance``
    c. Verify that the difference for Rx Frames Rate between the current
       traffic profile and and common_setup profile_traffic created golden
       traffic profile  is less than user provided threshold of ``rate_tolerance``

User's can define processor `compare_traffic_profile` in the `trigger_datafile`
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
                rate_tolerance: 2
                section_profile: /ws/ellewoods-sjc/genie/TriggerClearBgp_golden_profile

The `compare_traffic_profile` post-trigger processor has the following arguments:

1. [Optional] clear_stats: Controls executing clearing of traffic statistics before creating a traffic profile snapshot. Default: True.
2. [Optional] clear_stats_time: Time to wait after clear traffic stats. Default: 30 seconds.
3. [Optional] view_create_interval: Time to wait for custom traffic statistics view 'GENIE' to stabilize (if not previously created & stabilized). Default: 30 seconds.
4. [Optional] view_create_iteration: Maximum attempts to check if traffic statistics view 'GENIE' is stable (if not previously created & stabilized). Default: 10 attempts.
5. [Optional] loss_tolerance: Maximum difference between loss% of both profiles. Default: 2%.
6. [Optional] rate_tolerance: Maximum difference between rate loss of both profiles. Default: 2 (packets per second).
7. [Optional] section_profile: Golden traffic profile for this Trigger to be used for comparison between profiles

The parameters above can also be set at both the local processor and global
processor level with the exception of argument 'section_profile', which can only
be set at the trigger level.

