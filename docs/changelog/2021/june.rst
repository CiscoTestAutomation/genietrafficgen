June 2021
=========

June 29 - Genietrafficgen v21.6
-------------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 21.6                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New
--------------------------------------------------------------------------------

* ixiarestpy
    * Added ixiarestpy based on ixnetwork_restpy

* genie.trafficgen
    * Implemented abstraction
        * Use `os ixianative|ixiarestpy|trex` to select connection type


--------------------------------------------------------------------------------
                                      Fix
--------------------------------------------------------------------------------

* ixianative
    * Enhanced exception message in check_traffic_loss
        * only 1 traffic item is not supported. error clearly mentions.


