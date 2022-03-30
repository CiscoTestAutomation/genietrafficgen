February 2022
==========

February 24 - Genietrafficgen v22.3 
------------------------



+-------------------------------+-------------------------------+
| Module                        | Versions                      |
+===============================+===============================+
| ``genie.trafficgen``          | 22.2                          |
+-------------------------------+-------------------------------+




Changelogs
^^^^^^^^^^

--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* root
    * Modified setup.py
        * Updated package_data path from 'src/genie/trafficgen/ios/pagent/templates/*.ptd' to 'ios/pagent/templates/*.ptd'

* ixia restpy
    * Updated secret string handling for testbed password


--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* root
    * Modified setup.py
        * Updated package_data to include pagent template files

* pagent
    * Add start_pkt_count_arp
        * Add API of counting arp packet based on vlan information and ethernet header

* pagentflow
    * Add PG_flow_caputre_l2
        * Add class of counting packet back on vlan and ethernet header

