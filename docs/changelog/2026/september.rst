September 2026
==============

September 29 - Genietrafficgen v26.9
------------------------------------



.. csv-table:: New Module Versions
    :header: "Modules", "Version"

    ``genie.trafficgen``, v26.9




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New
--------------------------------------------------------------------------------

* genie.trafficgen.otg
    * Added Otg
        * New traffic generator plugin for the Open Traffic Generator (OTG) model, selected with `os: otg`, supporting `mock`, `http`, `https` and `grpc` transports.
        * Added legacy compatibility mode translating the imperative TrafficGen APIs into declarative OTG ports, emulated devices and flows.
        * Added native declarative mode exposing the snappi api, config, new_config, set_config, set_state and get_metrics handles.
        * Added Genie harness support covering load_configuration, remove_configuration, apply_traffic, assign_ixia_ports, start_all_protocols, stop_all_protocols, get_traffic_stream_names, generate_traffic_streams, create_genie_statistics_view, get_current_packet_rate, get_reference_packet_rate, create_traffic_streams_table, get_golden_profile and compare_traffic_profile.
        * Added an `ext` connection key selecting a snappi extension, so `os: otg` can drive IxNetwork through snappi_ixnetwork.
        * Added emulated endpoints for both the source and the destination of a data traffic stream, binding flows to device endpoints so the MAC addresses resolve by ARP and Neighbor Discovery. Pass `emulate_destination=False` to bind to ports instead.
        * Added next hop derivation from the testbed link peer, with `gateway` and `dst_gateway` overrides.
        * Added five tier receiving port inference so flows always bind a receiving endpoint and report Rx counters.
        * Added counter baselining for clear_statistics, including detection of backends such as IxNetwork that zero a flow's counters when traffic starts.
        * Added an in-memory OTG simulator behind `transport: mock` for hardware-free development and regression testing.
        * Added archiving of the configuration passed to load_configuration into the pyATS runtime directory, so the traffic configuration a run used is kept with its results. Nothing is written when running outside easypy, and a failure to archive warns without failing the run.
        * Added `snappi` as an optional dependency, installed with `pip install genie.trafficgen[otg]` and imported lazily.


