April 2022
==========

April 26 - Genietrafficgen v22.4 
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 22.4                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* trex
    * Added print_subinterface_stats API
    * Added disable_all_subinterface_emulation API
    * Added clear_traffic API


--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* trex
    * enable_subinterface_emulation
        * Added count parameter
    * configure_na
        * Added options to increment the IP/MAC of NA packets
    * configure_garp
        * Added options to increment the IP/MAC of GARP packets


