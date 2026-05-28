May 2026
==========

May 26 - Genietrafficgen v26.5  
------------------------



.. csv-table:: New Module Versions
    :header: "Modules", "Version"

    ``genie.trafficgen``, v26.5 




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* ixia
    * Modified IxiaNative
        * Normalized ixia_license_server_ip values from strings and lists before configuring IxNetwork license servers.
        * Configured license servers on the IxNetwork licensing object instead of passing them through connect arguments.


--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* trex
    * Add a new method `start_single_traffic_stream` to start a single traffic stream in Trex
        * def start_single_traffic_stream(self, port, stream_name, wait_time=5)
        * This method allows users to start a specific traffic stream on a given port.
        * Default traffic sending time is 5 seconds.
        * Example usage
            * self.tgen.start_single_traffic_stream(port=0, stream_name="4to6_udp", wait_time=10)


