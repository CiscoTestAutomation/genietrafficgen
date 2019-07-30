July 2019
=========

July 30th
---------

+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 19.7                          |
+-------------------------------+-------------------------------+


Features:
^^^^^^^^^
* Save and export "Flow Statistics" data as a CSV snapshot
* Check traffic loss for each flow group of parent traffic stream
* Disconnect/automatically reconnect when Ixia connection is reset
* Enable/disable assigning physical ports to virtual ::ixNet:: ports
* Enhanced logging for check_traffic_loss for traffic streams
* Get packet size per traffic stream or per flow group
* Get packet rate per traffic stream or per flow group
* Get layer2 bit rate per flow group or per flow group
* Get line rate per flow group or per flow group
* Find Traffic Stream, Flow Group and Quick Flow Group, QuickTest ::ixNet:: objects from name
* Enhancement for set packet size to enable/disable starting traffic after change
* Enhancement for set packet rate to enable/disable starting traffic after change
* Enhancement for set line rate to enable/disable starting traffic after change
* Enhancement for set layer2 bit rate to enable/disable starting traffic after change
* Get QuickTest results attributes
* Bugfix: Traffic streams with exact same "name" not printing in logs
* Bugfix: Get multi-page statistics data for custom "GENIE" view
