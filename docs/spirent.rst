.. _spirent:

Spirent
=======

``genie.trafficgen`` can connect to Spirent TestCenter via the ReST API. You can 
pre-install either the Spirent TestCenter application or Spirent LabServer to 
provide the ReST API service.



System Requirements
-------------------

1. Spirent TestCenter version 5.52 or later is recommended.
2. The `stcrestclient <https://pypi.org/project/stcrestclient/>`_ PyPI package (version 1.9.3 or above) must be Installed.
3. Using an internal network to connect to Spirent TestCenter is recommended to minimize security risks and latency issues.


Adding Spirent device
----------------------

An Spirent traffic generator `device` can be specified in the ``testbed`` YAML file
as shown in the example below:


.. code-block:: yaml

    devices:
      spirent:
        type: tgn
        os: 'tgn'
        connections:
          tgn:
            class: genie.trafficgen.spirent.Spirent
            server_ip: 192.168.10.1
            server_port: 80
            user_name: testid
            session_name: session
            chassis: 
            - ip: 192.168.20.1 
              port_list: ['1/1', '1/2'] 
            - ip: 192.168.20.2
              port_list: '1/1'


It is **mandatory** to specify a connection named `tgn` along with the 
connection manager details for the Spirent device in the testbed YAML file as shown
in the example above.

.. tip::

    1. The `type` key must be set to `tgn`.
    2. The `os` key specifies which OS implementation to use to connect to this
       device. Use `tgn` for Spirent.
    3. The `connections` key specifies the connection label which **must**
       contain a connection labelled `tgn`.


The following are mandatory keys to be provided in the `testbed` YAML while
defining an Spirent `device`:

.. code-block:: text

    +--------------------------------------------------------------------------+
    | Spirent Testbed YAML Parameters                                          |
    +==========================================================================+
    | Argument                 | Description                                   |
    |--------------------------+-----------------------------------------------|
    | class                    | Connection class implementation information.  |
    |--------------------------+-----------------------------------------------|
    | server_ip                | IP address of Spirent Labserver               |
    |--------------------------+-----------------------------------------------|
    | server_port              | Port of Spirent Labserver, default 80.        |
    |--------------------------+-----------------------------------------------|
    | user_name                | Identity of the user that owns the session.   |
    |                          | This is not a form of authentication,         |
    |                          | but is only a label for the test session.     |
    |--------------------------+-----------------------------------------------|
    | session_name             | Session name used as session ID.              |
    |--------------------------+-----------------------------------------------|
    | chassis                  | Spirent Chassis.                              |
    +==========================================================================+

Genie Trafficgen Use Cases
--------------------------

The following sections provide sample use cases for performing operations on 
traffic generator devices.

Connect to Spirent
^^^^^^^^^^^^^^^^^^

After specifying the spirent `device` in the `testbed` YAML file, we can connect to
the device using the `connect()` method:

.. code-block:: python

    Welcome to pyATS Interactive Shell
    ==================================
    Python 3.10.4 (main, Jul 26 2024, 23:11:00) [GCC 6.3.0 20170516]
    >>> from pyats.topology.loader import load
    >>> testbed = load('spirent_testbed.yaml')
    -------------------------------------------------------------------------------
    >>> dev = testbed.devices['spirent']
    >>>
    >>> dev.connect(via='tgn')
    +==============================================================================+
    | Spirent Configuration Details                                                |
    +==============================================================================+
    | Spirent API Server: 192.168.10.1:80                                          |
    |------------------------------------------------------------------------------|
    | Spirent Session: session - testid                                            |
    |------------------------------------------------------------------------------|
    | Spirent Chassis: ['//192.168.20.1/1/1', '//192.168.20.2/1/1']                |
    |------------------------------------------------------------------------------|
    For more information, see Genie traffic documentation: 
      https://pubhub.devnetcloud.com/media/genietrafficgen-docs/docs/spirent.html
    +------------------------------------------------------------------------------+
    |                            Connecting to Spirent                             |
    +------------------------------------------------------------------------------+
    Created new session:session - testid
    Connected to Spirent API server '192.168.10.1:80'


Load configuration onto Spirent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates loading a static configuration file onto an Spirent device

.. code-block:: python

    # Load static configuration file
    >>> dev.load_configuration('/root/genietrafficgen/traffic.xml')
    +------------------------------------------------------------------------------+
    |                            Loading configuration                             |
    +------------------------------------------------------------------------------+
    +==============================================================================+
    | Spirent Configuration Information                                            |
    +==============================================================================+
    | File: /root/genietrafficgen/traffic.xml                                      |
    |------------------------------------------------------------------------------|
    Loaded configuration file '/root/genietrafficgen/traffic.xml' onto device 'spirent'
    Waiting for '60' seconds after loading configuration...


.. note::

    ``traffic.xml`` is the XML configuration file generated via the Spirent TestCenter GUI. 
    In the GUI, choose File / Save As, and then set Save as type to Xml files.


Applying L2/L3 Traffic on Spirent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates how to apply loaded traffic on Spirent

.. code-block:: python

    # Apply traffic
    >>> dev.apply_traffic()
    +------------------------------------------------------------------------------+
    |                            Applying L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Applied L2/L3 traffic on device 'spirent'
    Waiting for '60' seconds after applying L2/L3 traffic...
    >>>


Start/Stop Routing Protocols on Spirent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates starting/stopping routing protocols on an Spirent device

.. code-block:: python

    # Start protocols
    >>> dev.start_all_protocols()
    +------------------------------------------------------------------------------+
    |                           Starting routing engine                            |
    +------------------------------------------------------------------------------+
    Started protocols on device 'spirent'
    Waiting for '60' seconds after starting all protocols...
    >>>
    # Stop protocols
    >>> dev.stop_all_protocols()
    +------------------------------------------------------------------------------+
    |                           Stopping routing engine                            |
    +------------------------------------------------------------------------------+
    Stopped protocols on device 'spirent'
    Waiting for  '60' seconds after stopping all protocols...
    >>>


Start/Stop Traffic on Spirent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates starting/stopping traffic on an Spirent device

.. code-block:: python

    # Start traffic
    >>> dev.start_traffic()
    +------------------------------------------------------------------------------+
    |                            Starting L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Startted L2/L3 traffic on device 'spirent'
    Waiting for '60' seconds after after starting L2/L3 traffic for streams to converge to steady state...
    >>>
    # Stop traffic
    >>> dev.stop_traffic()
    +------------------------------------------------------------------------------+
    |                            Stopping L2/L3 traffic                            |
    +------------------------------------------------------------------------------+
    Stopped L2/L3 traffic on device 'spirent'
    >>>


Start/Stop Capture on Spirent Ports
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates starting/stopping capture on an Spirent device ports

.. code-block:: python

    # Start capture 
    >>> dev.start_packet_capture_tgn()
    Starting packet capture...
    Waiting for '60' seconds after capture started.
    >>>
    # Stop capture
    >>> dev.stop_packet_capture_tgn()
    Stop packet capture...
    >>>


Save/Export Capture File on Spirent Ports
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates saving/exporting capture on an Spirent device ports

.. code-block:: python

    # Save capture file
    >>> dev.save_packet_capture_file("port1 //192.168.20.1/1/1", "data", "port1_traffic")
    Saving packet capture file /tmp/port1_HW_port1_traffic.cap
    '/tmp/port1_HW_port1_traffic.cap'
    >>>
    # Export capture file to local folder
    >>> dev.export_packet_capture_file("/tmp/port1_HW_port1_traffic.cap", "port1_spirent.cap")
    Export captured pcap file...
    Succeed to export capture file to 'port1_spirent.cap'.
    '/root/genietrafficgen/genietrafficgen/src/genie/trafficgen/port1_spirent.cap'
    >>>


.. note::

    ``port1 //192.168.20.1/1/1`` is the total port name for captured port, you can get it 
    via ``get_port_names_table`` function.   


Check for traffic loss on Spirent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates how to check for traffic loss on an Spirent device

.. code-block:: python

    >>> dev.create_genie_statistics_view()
    +------------------------------------------------------------------------------+
    |         Creating new custom Spirent traffic statistics view 'GENIE'          |
    +------------------------------------------------------------------------------+
    Create Spirent Dynamic View
    >>>
    # Check traffic loss for all configured streams
    >>> dev.check_traffic_loss(check_iteration=1)
    +------------------------------------------------------------------------------+
    |                  Check for traffic loss on a traffic stream                  |
    +------------------------------------------------------------------------------+
    +------------------------------------------------------------------------------+
    |                         Create traffic stream table                          |
    +------------------------------------------------------------------------------+
    Create Traffic Stream Table of DRV type
    +-------------------------------------+
    | Trying to get dynamic view of GENIE |
    +-------------------------------------+
    No DynamicResultView with name GENIE found!
    Create Spirent Dynamic View
    Create Dynamic view with DRV:dynamicresultview2, DRV Result:presentationresultquery2
    +-----------------------+------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    | Source/Dest Port Pair | Traffic Item     | Tx Frames | Rx Frames | Frames Delta | Tx Frame Rate | Rx Frame Rate | Loss % | Outage (seconds) |
    +-----------------------+------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    | port2-port1           | StreamBlock 8-2  | 49260     | 50537     | 0            | 4223          | 4223          | 0.0    | 0.0              |
    | port2-port1           | StreamBlock 11-2 | 49260     | 50536     | 0            | 4223          | 4223          | 0.0    | 0.0              |
    | port1-port2           | StreamBlock 8-1  | 49249     | 50488     | 0            | 4223          | 4223          | 0.0    | 0.0              |
    | port1-port2           | StreamBlock 11-1 | 49248     | 50488     | 0            | 4223          | 4223          | 0.0    | 0.0              |
    +-----------------------+------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    Attempt #1: Checking for traffic outage/loss
    +------------------------------------------------------------------------------+
    |           Checking traffic stream: 'port2-port1 | StreamBlock 8-2'           |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '0.0' seconds is within expected maximum outage threshold of '120' seconds
    outage: 0.0 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 0.0% is within maximum expected loss tolerance of 15%
    loss_percentage: 0.0 15 True
    +------------------------------------------------------------------------------+
    |          Checking traffic stream: 'port2-port1 | StreamBlock 11-2'           |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '0.0' seconds is within expected maximum outage threshold of '120' seconds
    outage: 0.0 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 0.0% is within maximum expected loss tolerance of 15%
    loss_percentage: 0.0 15 True
    +------------------------------------------------------------------------------+
    |           Checking traffic stream: 'port1-port2 | StreamBlock 8-1'           |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '0.0' seconds is within expected maximum outage threshold of '120' seconds
    outage: 0.0 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 0.0% is within maximum expected loss tolerance of 15%
    loss_percentage: 0.0 15 True
    +------------------------------------------------------------------------------+
    |          Checking traffic stream: 'port1-port2 | StreamBlock 11-1'           |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '0.0' seconds is within expected maximum outage threshold of '120' seconds
    outage: 0.0 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 0.0% is within maximum expected loss tolerance of 15%
    loss_percentage: 0.0 15 True
    Successfully verified traffic outages/loss is within tolerance for given traffic streams
    [{'stream': {'port2-port1': {'Source/Dest Port Pair': 'port2-port1', 'Traffic Item': 'StreamBlock 11-2', 'Tx Frames': 49260, 'Rx Frames': 50536, 'Frames Delta': 0, 'Tx Frame Rate': 4223, 'Rx Frame Rate': 4223, 'Loss %': 0.0, 'Outage (seconds)': 0.0}, 'port1-port2': {'Source/Dest Port Pair': 'port1-port2', 'Traffic Item': 'StreamBlock 11-1', 'Tx Frames': 49248, 'Rx Frames': 50488, 'Frames Delta': 0, 'Tx Frame Rate': 4223, 'Rx Frame Rate': 4223, 'Loss %': 0.0, 'Outage (seconds)': 0.0}}}]
    >>>


Traffic Generator Methods
-------------------------
The following table contains a list of available methods/actions to perform on
an Spirent traffic generator device:

.. code-block:: text

    +----------------------------------------------------------------------------------+
    | Traffic Generator Methods                                                        |
    +==================================================================================+
    | Methods                         | Description                                    |
    |---------------------------------+------------------------------------------------|
    | connect                         | Connect to Spirent traffic generator device.   |
    |                                 | Arguments:                                     |
    |                                 |     * [O] via - In mapping datafile.           |
    |---------------------------------+------------------------------------------------|
    | disconnect                      | Disconnect from Spirent traffic generator      |
    |                                 | device.                                        |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | load_configuration              | Loads the configuration onto Spirent device.   |
    |                                 | Arguments:                                     |
    |                                 |     * [M] configuration - static configuration |
    |                                 |           file for Spirent.                    |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           loading configuration file.          |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | save_confiugration              | Saving existing configuration on Spirent into  |
    |                                 | the specified file.                            |
    |                                 | Arguments:                                     |
    |                                 |     * [M] config_file - Complete write-able    |
    |                                 |           filepath and filename to copy Spirent|
    |                                 |           configuration to.                    |
    |---------------------------------+------------------------------------------------|
    | start_all_protocols             | Starts all protocols on Spirent device.        |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting all protocols on Spirent.   |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_all_protocols              | Stops all protocols on Spirent device.         |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping all protocols on Spirent.   |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | apply_traffic                   | Apply L2/L3 traffic on Spirent device.         |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           applying L2/L3 traffic on Spirent.   |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | send_arp                        | Send ARP to all interfaces from Spirent device.|
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           sending ARP to all interfaces.       |
    |                                 |           Default: 10 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | start_traffic                   | Starts L2/L3 traffic on Spirent device.        |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting L2/L3 traffic on Spirent.   |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_traffic                    | Stops L2/L3 traffic on Spirent device.         |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping L2/L3 traffic on Spirent.   |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | clear_statistics                | Clears L2/L3 traffic statistics on Spirent     |
    |                                 | device.                                        |
    |                                 | Arguments:                                     |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           clearing protocol and traffic        |
    |                                 |           statistics on Spirent.               |
    |                                 |           Default: 10 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | create_genie_statistics_view    | Creates a custom statistics view on Spirent    |
    |                                 | named "GENIE" with the required data fields    |
    |                                 | needed for processors.                         |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | check_traffic_loss              | Checks all traffic streams for traffic loss.   |
    |                                 | For each traffic stream configured on Spirent: |
    |                                 |   1. Verify traffic outage (in seconds) is less|
    |                                 |      than tolerance threshold value.           |
    |                                 |   2. Verify current loss % is less than        |
    |                                 |      tolerance threshold value.                |
    |                                 | Arguments:                                     |
    |                                 |     * [O] max_outage - maximum outage expected |
    |                                 |           in packets/frames per second.        |
    |                                 |           Default: 120 (seconds)               |
    |                                 |     * [O] loss_tolerance - maximum traffic loss|
    |                                 |           expected in percentage %.            |
    |                                 |           Default: 15%.                        |
    |                                 |     * [O] check_interval - wait time between   |
    |                                 |           traffic loss checks on Spirent.      |
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
    |                                 |     * [0] raise_on_loss - raise exception if   |
    |                                 |           traffic loss observed.               |
    |                                 |           Default: True.                       |
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
    |---------------------------------+------------------------------------------------|
    | compare_traffic_profile         | Compares values between two Spirent traffic    |
    |                                 | table statistics created.                      |
    |                                 | Arguments:                                     |
    |                                 |     * [M] profile1 - 1st traffic profile       |
    |                                 |     * [M] profile2 - 2nd traffic profile       |
    |                                 |     * [O] loss_tolerance - maximum expected    |
    |                                 |           difference between loss % statistics |
    |                                 |           between both traffic profiles.       |
    |                                 |           Default: 5%                          |
    |                                 |     * [O] rate_tolerance - maximum expected    |
    |                                 |           difference of Tx Rate & Rx Rate      |
    |                                 |           between both traffic profiles.       |
    |                                 |           Default: 2 (packets per second)      |
    |----------------------------------------------------------------------------------|
    |                               Others                                             |
    |----------------------------------------------------------------------------------|
    | get_golden_profile              | Returns the "golden" traffic profile in Python |
    |                                 | PrettyTable format. If not set, returns empty  |
    |                                 | table.                                         |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    | start_traffic_stream            | Start specific traffic item/stream via name    |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to start traffic on.                 |
    |                                 |     * [O] check_stream - check traffic stream  |
    |                                 |           to ensure Tx Rate is greater than    |
    |                                 |            0 pps.                              |
    |                                 |           Default: True                        |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           starting traffic stream to ensure Tx |
    |                                 |           Rate is greater than 0 pps.          |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] max_time - the max time to wait after|
    |                                 |           starting traffic stream.             |
    |                                 |           Default: 180 (seconds)               |
    |---------------------------------+------------------------------------------------|
    | stop_traffic_stream             | Stop specific traffic item/stream via name     |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to stop traffic on.                  |
    |                                 |     * [O] wait_time - time to wait after       |
    |                                 |           stopping traffic stream to ensure Tx |
    |                                 |           Rate is 0 pps.                       |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | set_line_rate                   | Set the line rate for given traffic stream.    |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the line rate.             |
    |                                 |     * [M] rate - New value to set/configure the|
    |                                 |           line rate to.                        |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           line rate for given traffic stream.  |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic after setting the   |
    |                                 |           line rate.                           |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           line rate for given traffic stream.  |
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | set_packet_rate                 | Set the packet rate for given traffic stream.  |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the packet rate.           |
    |                                 |     * [M] rate - New value to set/configure the|
    |                                 |           packet rate to.                      |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic after setting the   |
    |                                 |           line rate.                           |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | set_layer2_bit_rate             | Set the layer2 bit rate for given traffic      |
    |                                 | stream.                                        |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to modify the layer2 bit rate.       |
    |                                 |     * [M] rate - New value to set/configure the|
    |                                 |           layer2 bit rate to.                  |
    |                                 |     * [M] rate_units - For layer2 bit rate,    |
    |                                 |           specify the units to set the value.  |
    |                                 |           Valid Options: - bps                 |
    |                                 |                          - kbps                |
    |                                 |                          - mbps                |
    |                                 |                          - l2_bps              |
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           layer2 bit rate for given traffic    |
    |                                 |           stream.                              |
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic after setting the   |
    |                                 |           layer2 bit rate.                     |
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
    |                                 |     * [O] apply_traffic_time - time to wait    |
    |                                 |           after applying traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |                                 |     * [O] start_traffic - enable/disable       |
    |                                 |           starting traffic after setting the   |
    |                                 |           packet rate.                         |
    |                                 |           Default: True                        |
    |                                 |     * [O] start_traffic_time - time to wait    |
    |                                 |           after starting traffic for setting   |
    |                                 |           packet rate for given traffic stream.|
    |                                 |           Default: 15 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | get_line_rate                   | Returns the currently configured line rate for |
    |                                 | the traffic stream provided.                   |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the line rate of.             |
    |---------------------------------+------------------------------------------------|
    | get_packet_rate                 | Returns the currently configured packet rate   |
    |                                 | for the traffic stream provided.               |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the packet rate of.           |
    |---------------------------------+------------------------------------------------|
    | get_layer2_bit_rate             | Returns the currently configured layer2 bit    |
    |                                 | rate for the traffic stream provided.          |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the layer2 bit rate of.       |
    |---------------------------------+------------------------------------------------|
    | get_packet_size                 | Returns the currently configured packet size   |
    |                                 | for the traffic stream provided.               |
    |                                 | Arguments:                                     |
    |                                 |     * [M] traffic_stream - traffic stream name |
    |                                 |           to get the packet size of.           |
    |---------------------------------+------------------------------------------------|
    | start_packet_capture_tgn        | Starts packet capture on all ports.            |
    |                                 | Arguments:                                     |
    |                                 |     * [O] capture_time - Time to wait while    |
    |                                 |           packet capture is occurring.         |
    |                                 |           Default: 60 (seconds)                |
    |---------------------------------+------------------------------------------------|
    | stop_packet_capture_tgn         | Stops packet capture on all ports.             |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |---------------------------------+------------------------------------------------|
    | save_packet_capture_file        | Saves the packet capture file as specified     |
    |                                 | filename to desired location.                  |
    |                                 | Arguments:                                     |
    |                                 |     * [M] port_name - port on which packet     |
    |                                 |           capture session was performed.       |
    |                                 |     * [M] pcap_type - specify either data or   |
    |                                 |           control packet capture type.         |
    |                                 |     * [M] filename - destination filename to   |
    |                                 |           save packet capture file.            |
    |                                 |     * [O] directory - destination directory to |
    |                                 |           save packet capture file.            |
    |                                 |           Default: '/tmp' on linux server      |
    |---------------------------------+------------------------------------------------|
    | export_packet_capture_file      | Export packet capture file to runtime logs as  |
    |                                 | the given filename and return file path of the |
    |                                 | copied file to caller.                         |
    |                                 | Arguments:                                     |
    |                                 |     * [M] src_file - the name of packet capture|
    |                                 |           on spirent ReST API server.          |
    |                                 |     * [O] dest_file - filename to download the |
    |                                 |           packet capture file to runtime logs. |
    |                                 |           Default: 'spirent.pcap'              |
    |----------------------------------------------------------------------------------|
    | get_traffic_stream_names        | Returns a list of all traffic stream names     |
    |                                 | present in current configuration.              |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    | get_traffic_stream_objects      | Returns a list of all traffic stream objects   |
    |                                 | in current configuration.                      |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    | get_port_names_table            | Returns a prettytable of all port objects in   |
    |                                 | current configuration.                         |
    |                                 | Arguments:                                     |
    |                                 |     None                                       |
    |----------------------------------------------------------------------------------|
    | save_result_database            | Save database file for all results data to     |
    |                                 | expected folder.                               |
    |                                 | Arguments:                                     |
    |                                 |     * [M] file_name - file name without file   |
    |                                 |           extention to save result database    |
    |                                 |           file.                                |
    |                                 |     * [O] file_path - file path to save result |
    |                                 |           database file.                       |
    |----------------------------------------------------------------------------------|
    | save_statistics_snapshot_csv    | Save statistics view 'GENIE' snapshot as a CSV |
    |                                 | Arguments:                                     |
    |                                 |     * [M] view_name - name of statistic view to|
    |                                 |           take CSV snapshot of. Can be only    |
    |                                 |           'GENIE'.                             |
    |                                 |     * [O] csv_file_name - file Name for saving |
    |                                 |           snapshot file.                       |
    |                                 |           Default: result_statistics.csv       |
    |                                 |     * [O] csv_save_path - file path to save    |
    |                                 |           the CSV snapshot file as.            |
    |                                 |           Default: ./                          |
    +==================================================================================+

The methods listed above can be executed directly on an Spirent traffic generator
device from a Python prompt or within ``Genie`` and ``pyATS`` scripts.

Traffic Generator Usage
-----------------------

This sections covers sample usage of executing available Spirent traffic generator
methods mentioned in the previous section.

.. code-block:: bash

    pyats shell --testbed-file spirent_testbed.yaml

.. code-block:: python

    Welcome to pyATS Interactive Shell
    ==================================
    Python 3.10.4 (main, Jul 26 2024, 23:11:00) [GCC 6.3.0 20170516]
    >>> from pyats.topology.loader import load
    >>> testbed = load('spirent_testbed.yaml')
    -------------------------------------------------------------------------------
    >>>
    # Specify the spirent device
    >> dev = testbed.devices['spirent']
    # Connect to the spirent device
    >> dev.connect(via='tgn')
    # Load configuration file
    >> dev.load_configuration('/root/genietrafficgen/traffic.xml')
    # Start traffic on the device
    >> dev.start_traffic()
    # Stop traffic on the device
    >> dev.stop_traffic()
    # Clear stats on the device
    >> dev.clear_statistics()


Traffic Generator Usage Via Genie Harness
-----------------------------------------

This sections covers sample usage of executing Spirent Traffic Generator via gRun and datafiles.

.. code-block:: bash

    pyats run job job.py --testbed-file spirent_testbed.yaml

Below is the example of job.py, which contains: trigger_datafile, subsection_datafile and config_datafile.

.. code-block:: python

    import os
    from pyats import aetest
    from genie.harness.main import gRun
    def main():
        test_path = os.path.dirname(os.path.abspath(__file__))
        gRun(trigger_uids=['IPTraffic'],
            trigger_datafile=test_path+'/spirent_trigger_datafile.yaml',
            subsection_datafile=test_path+'/spirent_subsession_datafile.yaml',
            config_datafile=test_path+'/spirent_config_datafile.yaml',
            tgn_disable_assign_ports=True,
        )


.. note::

    trigger_uids and trigger_datafile are related to user defined testcase which totally follows pyATS Genie framework.


Configure Datafile
^^^^^^^^^^^^^^^^^^

Below is the example of how to provide spirent configuration file via config_datafile

.. code-block:: yaml

    devices:
        spirent:
            1:
                config: /root/genietrafficgen/traffic.xml


Subsection Datafile
^^^^^^^^^^^^^^^^^^^

``Genie`` bundles the different steps involved with Spirent setup and configuration
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
      order: ['connect', 'initialize_traffic', 'profile_traffic']
    cleanup:
      sections:
        stop_traffic:
          method: genie.harness.commons.stop_traffic
      order: ['stop_traffic']


common_setup: initialize_traffic
""""""""""""""""""""""""""""""""

This subsection packages the various steps associated with Spirent setup such as
connection and loading static configuration, enabling protocols, starting
traffic, etc into one runnable subsection.

It performs the following steps in order:
    1. Connect to Spirent
    2. Load static configuration and assign Spirent ports
    3. Start all protocols
    4. Regenerate traffic streams
    5. Apply L2/L3 traffic configuration
    6. Send ARP packet to all interfaces from Spirent
    7. Start L2/L3 traffic
    8. Clear traffic statistics after streams have converged to steady state
    9. Create custom traffic statistics view on Spirent named "Genie"
    10. Check traffic loss % and frames loss across all configured traffic streams


common_setup: profile_traffic
"""""""""""""""""""""""""""""

This subsection packages all the steps associated with "profiling" traffic
streams configured on spirent.

It creates a snapshot/profile of all configured traffic streams and then copies 
this profile to the runtime logs as the "golden_traffic_profile" for the
current job/run.

It also saves this snapshot/profile as the "golden" traffic profile for the
current ``Genie`` run. This snapshot profile will then be used to compare traffic
profiles generated after trigger execution to ensure that the trigger did not
impact configured traffic streams.

This profile can also be saved and reused as a reference for comparison of
subsequent runs of ``profile_traffic`` subsection.

The user can pass in a ``golden`` traffic profile via the ``tgn-golden-profile``
argument to enable comparison of the current profile against the previously
established/verified/golden traffic profile snapshot.

This subsection performs the following:

    1. Connect to Spirent
    2. Create a snapshot profile of traffic streams configured on Spirent
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

Below is the example of job.py, which contains: golden profile.

.. code-block:: python

    :emphasize-lines: 15
    :linenos:
    import os
    from pyats import aetest
    # Needed for logic
    from pyats.datastructures.logic import And, Not, Or
    from genie.harness.main import gRun
    def main():
        test_path = os.path.dirname(os.path.abspath(__file__))
        gRun(
            trigger_datafile=test_path+'/blitz.yaml',
            subsection_datafile=test_path+'/spirent_subsession_datafile.yaml',
            mapping_datafile=test_path+'/mapping_datafile.yaml',
            config_datafile=test_path+'/spirent_config_datafile.yaml',
            tgn_disable_assign_ports=True,
            tgn_golden_profile=test_path+'/golden_profile',
            trigger_groups=And('all'),
        )


Spirent `golden_profile` is something like below:

.. code-block:: text

    +-----------------------+------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    | Source/Dest Port Pair | Traffic Item     | Tx Frames | Rx Frames | Frames Delta | Tx Frame Rate | Rx Frame Rate | Loss % | Outage (seconds) |
    +-----------------------+------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+
    | port2-port1           | StreamBlock 8-2  | 702693    | 705409    | 0            | 4223          | 4223          | 0.0    | 0.0              |
    | port2-port1           | StreamBlock 11-2 | 702693    | 705409    | 0            | 4223          | 4223          | 0.0    | 0.0              |
    | port1-port2           | StreamBlock 8-1  | 702697    | 705373    | 0            | 4223          | 4223          | 0.0    | 0.0              |
    | port1-port2           | StreamBlock 11-1 | 702696    | 705372    | 0            | 4223          | 4223          | 0.0    | 0.0              |
    +-----------------------+------------------+-----------+-----------+--------------+---------------+---------------+--------+------------------+


common_cleanup: stop_traffic
""""""""""""""""""""""""""""

This subsection stops all protocols and stops traffic on an Spirent `device`.

It performs the following steps in order:
    1. Connect to Spirent
    2. Stop all protocols on Spirent
    3. Stop traffic streams on Spirent

To enable/disable execution of this subsection, simply add/remove 'stop_traffic'
from the execution order of the 'cleanup' in the `subsection_datafile` YAML.

``Genie`` will wait for `tgn-stop-protocols-time` seconds after stopping all
protocols on Spirent for the action to be completed; it will then wait
for `tgn-stop-traffic-time` seconds after stopping traffic on Spirent for the
action to be completed.

By default, the traffic is **not** stopped on an Spirent `device` after ``Genie``
execution completes. This is useful for manual debugging on Spirent 
server after ``Genie`` harness job completes.


Traffic Generator Usage Via pyATS Blitz
---------------------------------------

The Blitz is a YAML-driven template that makes it easy to run a test case without having to know any knowledge of programming.
This sections covers the sample usage of executing Spirent Traffic Generator via pyATS Blitz.

.. code-block:: bash

    pyats run job job.py --testbed-file spirent_testbed.yaml

Below is the example of defining Blitz yaml in gRun:

.. code-block:: python

    import os
    from pyats import aetest
    # Needed for logic
    from pyats.datastructures.logic import And, Not, Or
    from genie.harness.main import gRun
    def main():
        test_path = os.path.dirname(os.path.abspath(__file__))
        gRun(trigger_datafile=test_path+'/blitz.yaml',
            subsection_datafile=test_path+'/spirent_subsession_datafile.yaml',
            mapping_datafile=test_path+'/mapping_datafile.yaml',
            config_datafile=test_path+'/spirent_config_datafile.yaml',
            tgn_disable_assign_ports=True,
            trigger_groups=And('all'),
        )


.. note::

    blitz.yaml is an example of YAML-driven test cases, which is provided by the user based on the test scenarios.
    If TGN is triggered via subsections, blitz.yaml only contains the actions of user's test case without any ``-tgn`` actions.
    Otherwise, just as the 2nd example below, the user can use action ``-tgn`` directly in the blitz.yaml to call any TGN API based on requirements.
    The 2nd example provides a more flexible way to use TGN.

1. pyATS Blitz: Trigger Traffic Generator via subsections

This way is quite the same as above except that trigger_datafile is Blitz testcase defined via yaml file.
In Blitz yaml file, no action of tgn is provided and Spirent Traffic Generator is triggered via 
the definition of mapping datafile as below:

.. code-block:: yaml

    devices:
        R1_xe:
            context: cli
            mapping:
                cli: cli
        spirent:
            context: tgn
            mapping:
                tgn: tgn


2. pyATS Blitz: Traffic Generator can be called together with other Blitz actions

Traffic generator (tgn) apis can be called in addition to the other existing apis via action ``-tgn``.
Below gives the example of integrating Traffic generator (tgn) apis directly into Blitz yaml

.. code-block:: yaml

    variables:
        device: R1_xe
        interfaces:
            - GigabitEthernet2
        description: configured by pyATS
    config_interface:
        groups: ["all", "config", "interface"]
        source:
            pkg: genie.libs.sdk
            class: triggers.blitz.blitz.Blitz
        test_sections:
            - default_interfaces:
                - loop:
                    loop_variable_name: intfs
                    value: "%{variables.interfaces}"
                    actions:
                    - configure:
                        device: "%{variables.device}"
                        command: |
                            default interface %VARIABLES{intfs}
                    - tgn:
                        device: spirent
                        function: connect
              - tgn:
                  device: spirent
                  function: load_configuration
                  arguments:
                    configuration: "/root/genietrafficgen/traffic.xml"
              - tgn:
                  device: spirent
                  function: start_packet_capture
                  arguments:
                    capture_time: 30
              - tgn:
                  device: spirent
                  function: set_line_rate
                  arguments:
                    traffic_stream: "Traffic IPv4-1"
                    rate: 40
              - tgn:
                  device: spirent
                  function: set_packet_rate
                  arguments:
                    traffic_stream: "Traffic IPv6-3"
                    rate: 50
              - tgn:
                  device: spirent
                  function: set_layer2_bit_rate
                  arguments:
                    traffic_stream: "Traffic IPv6-4"
                    rate: 30
                    rate_unit: "kbps"
            - configure_interfaces:
                - loop:
                    loop_variable_name: intfs
                    value: "%{variables.interfaces}"
                    actions:
                    - configure:
                        device: "%{variables.device}"
                        command: |
                            interface %VARIABLES{intfs}
                            description %{variables.description}
            - verify_configuration:
                - loop:
                    loop_variable_name: intfs
                    value: "%{variables.interfaces}"
                    actions:
                    - parse:
                        device: "%{variables.device}"
                        command: show interfaces description
                        include:
                            - contains("%VARIABLES{intfs}").contains_key_value('description', "%{variables.description}")


In this way, mapping datafile shall remove the mapping of spirent TGN as below:

.. code-block:: yaml

    devices:
        R1_xe:
            context: cli
            mapping:
                cli: cli

