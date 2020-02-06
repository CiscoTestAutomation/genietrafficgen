January 2020
============

January 28
-----------

+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 20.1                          |
+-------------------------------+-------------------------------+

Features:
^^^^^^^^^

* Added remove_configuration() to clear all configuration from Ixia device
* Enhancement: Corner cases where tx_rate, rx_rate, loss % columns in 'Traffic Item Statistics' are either empty ('') or star ('*')
* Enhancement: stop_traffic - Updated to use genie timeout/iteration to verify traffic state after stopping
* Enhancement: start_traffic_stream - Updated to use genie timeout/iteration to verify traffic state after starting
