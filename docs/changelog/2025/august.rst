August 2025
==========

September 30 - Genietrafficgen v25.8 
------------------------



.. csv-table:: New Module Versions
    :header: "Modules", "Version"

    ``genie.trafficgen``, v25.8 




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixia
    * Modified IxiaNative
        * Added license mode and license tier support
        * Enhanced check_traffic_loss to handle missing "Traffic Item" column by using "Source/Dest Port Pair" as an alternative identifier
    * Modified IxiaNative
        * Enhanced license mode and tier configuration
            * Added debug logging for connection arguments
            * Implemented post-connection license configuration via licensing object
            * Added automatic detection and verification of current license settings
            * Added informative warnings when license changes fail
            * Added detailed logging of license configuration status


