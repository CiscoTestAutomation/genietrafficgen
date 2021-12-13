December 2021
==========

December 13 - Genietrafficgen v21.12
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 21.12                         |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* pagent
    * added API to configure dhcpv4 request/reply packets on pagent
    * Add clear_traffics
        * Add API to support clear streams
    * Add modify_trafic
        * Add API to support modify configured stream
    * Add configure_rawip
        * Add API to support raw ip stream configure
    * Add configure_rawipv6
        * Add API to support raw ipv6 stream configure
    * configure_dhcpv6_request
        * Added API to configure_dhcpv6_request through pagent
    * configure_dhcpv6_reply
        * Added API to configure_dhcpv6_reply through pagent

* pagentflow
    * Add configure_traffic
        * Add API for configuring stream on pagent to seperate the behaviors

* trex
    * added enable and disable subinterface emulation API implementation


--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* pagent
    * Modify start_traffic
        * To support start multi streams at same time, support start only
    * Modify stop_traffic
        * To support stop multi streams at same time, support stop only
    * Modified hardcoded hostname for creating Connection in pagent connect method
    * Modify modify_traffic
        * Correct the tgn stream select command to "tgn select xx"
    * Added send process complete expect call back

* pagentflow
    * Modified PG_flow_rawip
        * To remove hardcode for data-length, support flexible kwargs input
    * Modified PG_flow_rawipv6
        * To remove hardcode for data-length, support flexible kwargs input
    * Removed the Duplicate PG_flow_rawipv6 class
    * Modify stop_traffic
        * To support stop only but not delete the streams
    * Modified PG_flow_rawip
        * Correct kwargs for loop value
    * Modified PG_flow_rawipv6
        * Correct kwargs for loop value


