March 2022
==========

March 29 - Genietrafficgen v22.3 
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 22.3                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* trex
    * Modified implementation.py
        * Updated create_traffic_statistics_table to fill correct number of data points

* pagent
    * Added start_pkt_count_nd
        * added an API to count unicast ndp ns packets


--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixianative
    * Added support for credentials

* trex
    * Add missing options to configure_dhcpv6_request
    * Add missing options to configure_dhcpv6_reply

* pagent
    * Modified start_pkt_count_arp
        * Modified the api to count unicast arp packets based on more header fields

* pagentflow
    * Removed PG_flow_caputre_l2
        * This flow is no longer needed by the start_pkt_count_arp function
    * Modified PG_flow_arp_request
        * This function now takes a dmac argument to match unicast arp packets
    * Modified PG_flow_ndp_ns
        * This function now takes a dmac argument to match unicast ndp ns packets


