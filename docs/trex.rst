Trex
====

Trex requires the `trex_hltapi` package. Check https://trex.cisco.com/hltapi/installation.html#install-trex-hltapi

.. code-block:: yaml

    devices:
        trex:
            os: trex
            connections:
                defaults:
                    class: genie.trafficgen.TrafficGen

                hltapi:
                    device_ip: trex-host # hostname/IP address of machine where TRex is running
                    port: ssh-port # port to use when connecting via ssh, default 22
                    username: trex-hlt-user # username that will be used to acquire TRex ports
                    reset: true # should reset ports before test
                    break_locks: true # should force acquire TRex ports
                    raise_errors: true # should raise an exception on error, if false will return status = 0 and error message.
                    verbose: none # verbosity level of TRex client, available levels are: none, critical, error, info, debug
                    timeout: 15 # timeout of connection to TRex (increase if you have big delay)
                    port_list: []
                    ip_src_addr: 1.1.1.1
                    ip_dst_addr: 2.2.2.2
                    intf_ip_list: []
                    gw_ip_list: []
                    trex_path: /path/to/trex # path to the TRex installation, default /opt/trex
                    cfg_file: /path/to/trex_cfg_file # reference an existing config file when booting trex, default None
                    autostart: Boolean # check if the TRex process is running, and start it if not, default False
                    autostart_timeout: 30 # timeout value for attempting to start trex, default 60
