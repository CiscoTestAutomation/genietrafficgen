.. _spirent:

Spirent
=======

``genie.trafficgen`` can connect to Spirent traffic generator devices that are running
Spirent LabServer versions 5.52 or above. Refer to the user guide below for
detailed information on using ``Genie`` to control Spirent using the public PyPI
Package stcrestclient versions 1.9.3 or above.


System Requirements
-------------------

1. Spirent chassis with ports and active Spirent licenses
2. Spirent LabServer version 5.52 or above
3. Installed: `stcrestclient <https://pypi.org/project/stcrestclient/>`_ PyPI package (version 1.9.3 or above)

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
            server_ip: 10.61.67.191
            server_port: 80
            user_name: testid
            session_name: session
            chassis: 
            - ip: 10.109.127.27
              port_list: ['1/1', '1/2'] 
            - ip: 10.109.119.212
              port_list: '1/1' 

It is **mandatory** to specify a connection named 'tgn' along with the 
connection manager details for the Spirent device in the testbed YAML file as shown
in the example above.

.. tip::

    1. The `type` key must be set to "tgn".
    2. The `os` key specifies which OS implementation to use to connect to this
       device. Use "tgn" for Spirent.
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
    | Spirent API Server: 10.61.67.22:80                                           |
    |------------------------------------------------------------------------------|
    | Spirent Session: session - testid                                            |
    |------------------------------------------------------------------------------|
    | Spirent Chassis: ['//10.109.123.110/1/1', '//10.109.120.103/1/1']            |
    |------------------------------------------------------------------------------|
    For more information, see Genie traffic documentation: 
      https://pubhub.devnetcloud.com/media/genietrafficgen-docs/docs/spirent.html
    +------------------------------------------------------------------------------+
    |                            Connecting to Spirent                             |
    +------------------------------------------------------------------------------+
    Created new session:session - testid
    Connected to Spirent API server '10.61.67.22:80'



Load configuration onto Spirent
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following code block demonstrates loading a static configuration file onto an Spirnet device

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
    >>>


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

The following code block demonstrates starting/stopping routing protocols on an Spirnet device

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
    +-----------------------+----------------+-----------+-----------+--------------+--------+---------------+---------------+------------------+
    | Source/Dest Port Pair | Traffic Item   | Tx Frames | Rx Frames | Frames Delta | Loss % | Tx Frame Rate | Rx Frame Rate | Outage (seconds) |
    +-----------------------+----------------+-----------+-----------+--------------+--------+---------------+---------------+------------------+
    | PortA-PortB           | Traffic IPv4-1 | 11445947  | 11453819  | 1149         | 0.01   | 36170         | 36155         | 0.032            |
    | PortA-PortB           | Traffic IPv6-4 | 11445947  | 11453818  | 1150         | 0.01   | 36170         | 36155         | 0.032            |
    | PortB-PortA           | Traffic IPv4-0 | 13637814  | 11863085  | 1768024      | 12.97  | 42226         | 37273         | 41.871           |
    | PortB-PortA           | Traffic IPv6-3 | 13637813  | 11867720  | 1763388      | 12.94  | 42226         | 37262         | 41.761           |
    +-----------------------+----------------+-----------+-----------+--------------+--------+---------------+---------------+------------------+

    Attempt #1: Checking for traffic outage/loss
    Traffic IPv4-1
    +------------------------------------------------------------------------------+
    |            Checking traffic stream: 'Port-Port | Traffic IPv4-1'             |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '0.032' seconds is within expected maximum outage threshold of '120' seconds
    outage: 0.032 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 0.01% is within maximum expected loss tolerance of 15%
    loss_percentage: 0.01 15 True
    Traffic IPv6-4
    +------------------------------------------------------------------------------+
    |            Checking traffic stream: 'Port-Port | Traffic IPv6-4'             |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '0.032' seconds is within expected maximum outage threshold of '120' seconds
    outage: 0.032 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 0.01% is within maximum expected loss tolerance of 15%
    loss_percentage: 0.01 15 True
    Traffic IPv4-0
    +------------------------------------------------------------------------------+
    |            Checking traffic stream: 'Port-Port | Traffic IPv4-0'             |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '41.871' seconds is within expected maximum outage threshold of '120' seconds
    outage: 41.871 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 12.97% is within maximum expected loss tolerance of 15%
    loss_percentage: 12.97 15 True
    Traffic IPv6-3
    +------------------------------------------------------------------------------+
    |            Checking traffic stream: 'Port-Port | Traffic IPv6-3'             |
    +------------------------------------------------------------------------------+
    1. Verify traffic outage (in seconds) is less than tolerance threshold of '120' seconds
    * Traffic outage of '41.761' seconds is within expected maximum outage threshold of '120' seconds
    outage: 41.761 120 True
    2. Verify current loss % is less than tolerance threshold of '15' %
    * Current traffic loss of 12.94% is within maximum expected loss tolerance of 15%
    loss_percentage: 12.94 15 True

    Successfully verified traffic outages/loss is within tolerance for given traffic streams
    [{'stream': {'Port-Port': {'Source/Dest Port Pair': 'Port-Port', 'Traffic Item': 'Traffic IPv6-3', 'Tx Frames': 13637813, 'Rx Frames': 11867720, 'Frames Delta': 1763388, 'Loss %': 12.94, 'Tx Frame Rate': 42226, 'Rx Frame Rate': 37262, 'Outage (seconds)': 41.761}}}]
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
    |                                 |     * [O] clear_stats - flag to enable clearing|
    |                                 |           of all traffic statistics before     |
    |                                 |           checking for traffic loss/outage.    |
    |                                 |           Default: False                       |
    |                                 |     * [O] clear_stats_time - time to wait after|
    |                                 |           clearing all traffic statistics if   |
    |                                 |           enabled by user.                     |
    |                                 |           Default: 30 (seconds)                |
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

    pyats run job job.py --testbed-file spirent_testbed.yaml --tgn-disable-assign-ports True

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
    2. common_cleanup: stop_traffic

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

      order: ['connect', 'initialize_traffic']

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

    pyats run job job.py --testbed-file spirent_testbed.yaml --tgn-disable-assign-ports True

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
            - GigabitEthernet3
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

