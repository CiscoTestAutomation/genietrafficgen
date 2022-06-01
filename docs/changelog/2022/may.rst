--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* iosxe
    * Added DHCP emulator APIs on both pagent and Trex
        * add_dhcpv4_emulator_client
        * add_dhcpv6_emulator_client
        * get_dhcp_binding
        * clear_dhcp_emulator_clients
        * verify_dhcp_client_binding
        * get_dhcpv4_binding_address
        * get_dhcpv6_binding_address


--------------------------------------------------------------------------------
                                     Update                                     
--------------------------------------------------------------------------------

* trafficgen
    * Modified trafficgen
        * fixed method send_ndp_na
        * modified start_count series api, move them togather

* trex
    * Modified implementation
        * added method start_pkt_count_arp
        * added method start_pkt_count_nd
        * fixed methods send_rawip, send_rawipv6, send_rawipv6_mcast
        * moved start_pkt_count methods togather


--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixianative.py
    * Modified connect
        * Fixed so that it connects even when IXIA doesn't return apiKey

* implementation.py
    * Modified configure_interface
        * add port_list and other configurable parameters
    * Modified configure_traffic_profile
        * port_handle2 for bidirectional option
        * add other configurable parameters


