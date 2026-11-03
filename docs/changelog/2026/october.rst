October 2026
==========

October 27 - Genietrafficgen v26.10
-----------------------------------



.. csv-table:: New Module Versions
    :header: "Modules", "Version"

    ``genie.trafficgen``, v26.10




Changelogs
^^^^^^^^^^
--------------------------------------------------------------------------------
                                      New                                       
--------------------------------------------------------------------------------

* genie.trafficgen
    * Added traffic generator plugin discovery
        * Added the `genie.trafficgen` entry point. A package registered there joins the traffic generator abstraction lookup with its own tokens, so a testbed can select a traffic generator this package does not ship while keeping genie.trafficgen.TrafficGen as the connection class.
        * Added merged lookups across the discovered packages, in which a registered package supersedes the nodes it shares with genie.trafficgen.
        * Added skipping of a registered package that cannot be imported, learnt or merged, with a warning naming it, so one broken extension does not take down every traffic generator connection in a run.

* genie.trafficgen.otg
    * Added IxiaOtg
        * Added an OTG backend selected with `platform` set to `ixia`. It answers to every IxiaNative method name, so a script written for the ixianative plugin keeps its calls when its testbed moves to the OTG plugin; the connection and the traffic configuration take their OTG form.
        * Connects exactly as Otg does, so a device that already sets `platform` to `ixia` is unaffected. IxNetwork still needs the `ext` connection key set to `ixnetwork`, and a controller that speaks OTG natively needs no `ext`.
        * Added the IxNetwork-only IxiaNative methods (the object model, Quick Flow Groups, QuickTest, chassis and vport operations, and traffic item construction) as methods that report which IxNetwork construct they reach for and what to use instead, rather than failing with an AttributeError.
    * Modified Otg
        * Added a `platform` device key selecting the OTG backend. `ixia`, or omitted, is a controller that speaks the model natively; any other value is rejected with an error naming the `genie.trafficgen` entry point, rather than silently falling back.
        * Added backend hooks for a subclass to drive a traffic generator of its own (connection option validation, the default location, the API client and its release, configuration deserialising and source resolution, traffic no-ops, the update precondition, the default route names, the BGP peer names and the text save_configuration writes).
        * Added start_capture, stop_capture and save_capture for the OTG per-port packet captures.
        * Added get_bgp_metrics, verify_bgp_sessions and set_bgp_peer_state for the emulated BGP sessions. Peers are addressed by their OTG names and their state is changed without a configuration push.
        * Added the IxiaNative packet capture call signatures enable_data_packet_capture, disable_data_packet_capture, enable_control_packet_capture, disable_control_packet_capture, start_packet_capture, stop_packet_capture, get_packet_capture_count, get_packet_capture_data, save_packet_capture_file and export_packet_capture_file. OTG captures a port without the IxNetwork hardware and software split, so both pairs drive the one capture and `pcap_type` selects the counter or file name reported.
        * Added frame counting over both the classic pcap and the pcapng container, since snappi_ixnetwork answers a pcap request with pcapng.
        * Added the rate and frame size call signatures set_packet_rate, set_line_rate, set_layer2_bit_rate, set_packet_size_fixed, get_packet_rate, get_line_rate, get_layer2_bit_rate and get_packet_size. Each sets the matching OTG rate choice, and reading a rate the flow does not carry is an error rather than a zero.
        * Added the per-stream and flow group call signatures start_traffic_stream, stop_traffic_stream, get_flow_group_names, start_flow_group, stop_flow_group, check_flow_groups_loss and check_ecmp_traffic_loss. OTG has no subdivision of a stream, so a stream is its own flow group.
        * Added the statistics call signatures get_all_statistics_views, get_flow_statistics_data, get_traffic_items_statistics_data, create_flow_statistics_table, get_flow_statistics_table, get_traffic_item_statistics_table, get_traffic_items_from_genie_view and save_statistics_snapshot_csv. A Windows `csv_windows_path` addresses the IxNetwork host, so it is reported as ignored and the snapshot is written next to the run artifacts.
        * Added save_configuration, regenerate_all_traffic_items and get_traffic_attribute. get_traffic_attribute reports the flows' own transmit state rather than a local flag.
        * Modified update_traffic_profile to take the rate attribute to update, so a profile update can set a line rate or a bit rate and not only a packet rate. It still defaults to packets per second.
        * A refused live update puts back the flow's whole previous rate and frame size, its rate choice included, so a refused line rate change leaves a packet rate flow at its packet rate.
        * Modified set_state, get_metrics and get_states to accept a dict or JSON or YAML text as well as an OTG object, so a trigger datafile can carry the request.
        * Disabling packet capture on the last port of a capture removes the capture, which an OTG controller would refuse without ports at the next configuration push.
        * Added capture control and retrieval, configured captures and the OTG rate-choice model to the mock transport simulator, so these are exercised without a chassis. It records no packets, so a capture it is asked for comes back as an empty pcap file.
    * Modified Otg
        * Added apply_configuration for full native OTG configuration replacement from a file, mapping, JSON/YAML payload, or config object. Inline input is archived and its restart lifecycle resolves both IPv4 ARP and IPv6 neighbours before baselining statistics.
        * Documented native OTG configuration in Blitz through the existing generic ``tgn`` action; no OTG-specific Blitz action is required.
        * Added update_configuration for validated unique-name scalar changes, update_traffic_profile for live rate/frame-size updates, and set_route_state for route advertise/withdraw control.
        * Added `snappi` as a default package dependency, with its IxNetwork extension behind the new `genie.trafficgen[ixnetwork]` extra. The former `genie.trafficgen[otg]` extra remains an accepted alias; Snappi is still imported lazily.
        * Added an actionable error when an `ext` connection key names a snappi extension that is not installed, naming the package to install rather than failing inside snappi.
        * Added optional IxNetwork licensing configuration for ``ext: ixnetwork`` OTG testbeds. The license server, mode and tier are applied through a short-lived Tcl session before Snappi connects.
        * Simplified licensing validation, setting readback, and temporary session cleanup while preserving strict OTG errors and legacy warning-only handling. Preserved Snappi-compatible route names in the mock controller.


--------------------------------------------------------------------------------
                                      Fix                                       
--------------------------------------------------------------------------------

* genie.trafficgen.otg
    * Modified Otg
        * Fixed send_arp_request, which set ARP fields snappi does not have. It now sets sender_hardware_addr, sender_protocol_addr, target_hardware_addr and target_protocol_addr.
        * Fixed set_config with text that is not an OTG mapping, such as a file path, which pushed an empty configuration. It is now rejected with an error pointing to load_configuration.
        * Fixed verify_bgp_sessions to wait for all configured peers when controller metrics are temporarily empty or incomplete after protocol start, and to accept a single peer name.
        * Fixed get_bgp_metrics with snappi-ixnetwork, which filters and labels protocol metrics by device name. The plugin maps them back to OTG peer names and refuses ambiguous device groups.
        * Fixed set_bgp_peer_state with snappi-ixnetwork to report unsupported peer control instead of returning success for a request the extension silently ignores.
        * Fixed live rate and fixed-size compatibility setters to preserve running flows, starting only stopped flows when requested.
        * Fixed stream-start verification to require current started state and advancing Tx counters rather than historical nonzero counters.
        * Fixed mock flow-rate round trips and active-choice simulation. Fixed-frame bit rates now drive packet and byte metrics; percentage rates are rejected because the simulator has no link speed. Live updates retain accumulated counters and validate all selected flows before applying changes.
        * Fixed PPS reference lookup to avoid reading inactive rate choices or using their default values.
        * Fixed set_bgp_peer_state to reject invalid states and unconfigured IPv4/IPv6 peer names before sending control operations.
        * Fixed update_traffic_profile to reject unsupported rate_attribute values before committing configuration or changing a flow.
        * Fixed generated configuration archive and packet capture filenames to encode path separators and verify that resolved paths stay inside the selected destination directory. Explicit destination paths remain supported.
        * Fixed export_packet_capture_file and save_statistics_snapshot_csv to keep generated filenames inside their selected directories, including when a name contains path separators or an existing symlink points outside.
        * Fixed mock flow-rate and frame-size serialization to honor explicit dict, JSON and YAML encodings while preserving dictionary defaults and SDK-compatible method signatures.


