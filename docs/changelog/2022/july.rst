July 2022
==========

July 26 - Genietrafficgen v22.7
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 22.7                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixianative
    * Modified `check_traffic_loss` API
        * raise exception if no traffic data found
    * Modified `check_traffic_loss` API
        * Modified check_traffic_loss to work without source/dest port pair
        * Added `raise_on_loss` argument to raise an Exception on traffic loss (default is True).
        * Added `check_traffic_type` argument, set to False by default.
        * Note this changes the default behavior, previously the traffic type was always checked.
        * API will now return traffic stream data as list of dictionaries
    * Add check for duplicate stream names in `check_traffic_loss` API


