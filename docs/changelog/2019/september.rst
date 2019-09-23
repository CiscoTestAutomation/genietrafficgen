September 2019
==============

September 24th
--------------

+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 19.9                          |
+-------------------------------+-------------------------------+

Features:
^^^^^^^^^

* Enhanced clear_statistics() to control which commands to execute for clearing statistics
* Enhanced check_traffic_loss corner case to recreate "GENIE" view if deleted by previously executed command
* Bugfix: corner case for setting outage_seconds to 0 when frames_delta is "*" or empty string
