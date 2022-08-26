--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixianative
    * Modified `enable_subinterface_emulation` API
        * Modified enable_subinterface_emulation to get vlan id as input parameter.
        * Added 'vlan_id' argument as optional parameter (default is None).

* tests
    * Modified mock_data
        * Added line vty 0 4 to list of recorded commands

* trex
    * Modified igmp_client_control and mld_client_control API
        * When deleting an igmpv2 or mldv1 group restart the client with


