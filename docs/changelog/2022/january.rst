January 2022
==========

January 25 - Genietrafficgen v22.1
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 22.1                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* pagent
    * Add send_igmpv2_query_general
        * Add API of sending IGMPv2 general query message
    * Add send_mldv1_query_general
        * Add API of sending MLDv1 general query message
    * Add start_pkt_count_rawipv6_mcast
        * Add API of starting IPv6 multicast packet count
    * Add send_rawipv6_mcast
        * Add API of sending IPv6 multicast packet

* pagentflow
    * Add PG_flow_igmpv2_query_general
        * Add class of IGMPv2 general query packet flow
    * Add PG_flow_mldv1_query_general
        * Add class of MLDv1 general query packet flow

* trex
    * Add send_igmpv2_query_general
        * Add API of sending IGMPv2 general query message
    * Add send_mldv1_query_general
        * Add API of sending MLDv1 general query message
    * Add start_pkt_count_rawipv6_mcast
        * Add API of starting IPv6 multicast packet count
    * Add send_rawipv6_mcast
        * Add API of sending IPv6 multicast packet


--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* trex.implementation.py
    * Modified Trex
        * Modified configure_interface to accept "promiscuous" arugment as optional. Default set to False.


