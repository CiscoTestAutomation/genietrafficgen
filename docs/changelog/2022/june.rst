June 2022
==========

June 27 - Genietrafficgen v22.6 
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 22.6                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixianative/implementation.py
    * Modified check_traffic_loss
        * Modified check_traffic_loss to work without source/dest port pair
        * Added `raise_on_loss` argument to raise an Exception on traffic loss (default is True).
        * Added `check_traffic_type` argument, set to False by default.
        * Note this changes the default behavior, previously the traffic type was always checked.
        * API will now return traffic stream data as list of dictionaries


