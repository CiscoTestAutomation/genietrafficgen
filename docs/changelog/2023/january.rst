January 2023
==========

January 31 - Genietrafficgen v23.1 
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 23.1                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^



--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* trex
    * added 'autostart' to testbed which will have connect() check the server's TRex process and start if needed
    * Trex can now accept credentials to create Unicon connections to the host TRex server
    * Added trex_path to connection info if trex install location not /opt/trex

* ixiarestpy
    * Modified class Ixiarestpy
        * Added session name to find the session id which is active.
        * Added the timeout logic to loop through to find the state of chassis state.


--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* trex
    * reset_dhcp_session_config
        * This API resets dhcp session config
    * abort_dhcp_devx_session
        * This API aborts dhcp devx session
    * generate_dhcp_session_handle
        * This API configured dhcp session and returns its handle
    * add_dhcp_emulator_bvm_client
        * This API configures bvm dhcp clients
    * bind_dhcp_clients
        * This API binds the dhcp clients
    * verify_num_dhcp_clients_binding
        * This API verifies the number of clients got bound with dhcp
    * get_dhcp_client_ip_mac_details
        * This API returns a dictionary with ip as key and
    * add_dhcp_emulator_non_bvm_client
        * This API configures non bvm dhcp clients


