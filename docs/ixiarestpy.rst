
Ixia RESTpy
===========

The `ixiarestpy` module is the trafficgen implementation that uses `ixnetwork_restpy` to interface with Ixia devices.

The IxiaRestPy class can connect to Ixia traffic generator devices that are running IxNetwork API server versions 8.52 or higher.

For more documentation, see https://openixia.github.io/ixnetwork_restpy/#/ and https://github.com/OpenIxia/IxNetwork/tree/master/RestPy

Usage:


.. code-block:: yaml

    devices:
        IXIA:
            type: tgn
            os: ixiarestpy
            credentials:
                default:
                    username: admin  # optional
                    password: admin  # optional
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    ip: 192.0.0.1
                    port: 11009
                    chassis_ip: 192.0.0.2
                    log_level: info  # default: info
                    logfile: restpy.log  # default: None
                    clear_config: False  # default: False

                    # Parameters for the chassis (optional)
                    chain_topology: # Default: None
                    master_chassis: # Default: None
                    sequence_id: # Default: None
                    cable_length: # Default: None


Example script


.. code-block:: python


    from pyats.topology import loader

    testbed = loader.load('testbed.yaml')
    tgn = testbed.devices.IXIA

    tgn.connect()

    # The following objects are available to interact with:

    tgn.session     # Created via SessionAssistant
    tgn.ixnetwork   # SessionAssistant().Ixnetwork object

    # The request session is available for raw API calls:

    tgn.requests_session   # SessionAssistant().Ixnetwork._connection._session
