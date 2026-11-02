Open Traffic Generator (OTG)
============================

The ``otg`` plugin connects ``Genie`` to any traffic generator that implements
the `Open Traffic Generator <https://github.com/open-traffic-generator>`_ model
- for example Keysight ``ixia-c``, IxNetwork behind ``snappi-ixnetwork``, or a
containerised OTG controller running under Containerlab or KNE.

Unlike the vendor specific plugins, OTG is a declarative, model driven API: a
test describes the desired ports, emulated devices and flows as data, pushes
that configuration in one transaction, then drives the run through control
state transitions and reads typed metrics back.

The plugin offers two modes at the same time:

* **Legacy compatibility mode** - the existing imperative ``TrafficGen`` APIs
  (``configure_ipv4_data_traffic``, ``send_arp``, ``start_traffic``,
  ``check_traffic_loss``, ...) keep working, and are translated into OTG ports,
  devices and flows under the hood.
* **Native declarative mode** - ``tgn.api``, ``tgn.config``, ``tgn.new_config()``
  and ``tgn.set_config()`` expose the OTG schema directly, for tests written
  against ``snappi``.

Installation
------------

Install ``genie.trafficgen`` to get the ``snappi`` SDK by default::

    pip install genie.trafficgen

That covers every OTG controller that speaks the model natively, such as
``ixia-c`` and KENG. Driving IxNetwork needs the extension as well::

    pip install genie.trafficgen[ixnetwork]

The extension is a separate install because ``snappi_ixnetwork`` pins its own
dependency versions tightly, and testbeds that do not use it should not have
to satisfy those pins.

The former ``genie.trafficgen[otg]`` install syntax remains supported, but is
no longer necessary. ``snappi`` is still imported lazily; importing
``genie.trafficgen`` or using ``transport: mock`` does not load its gRPC
modules. A plain installation includes Snappi's upstream dependencies even
when only the mock transport is used.

Driving IxNetwork
^^^^^^^^^^^^^^^^^

IxNetwork does not speak OTG natively. ``snappi`` reaches it through the
``snappi_ixnetwork`` extension, selected with the ``ext`` connection key and
installed with ``pip install genie.trafficgen[ixnetwork]``. Connecting without
it raises a ``GenieTgnError`` naming the install command.

.. code-block:: yaml

    devices:
        otg:
            type: tgn
            os: otg
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    transport: http
                    protocol: http
                    ip: 10.0.0.10     # IxNetwork API server
                    port: 11009
                    ext: ixnetwork

    topology:
        otg:
            interfaces:
                1/1:
                    type: ethernet
                    ipv4: 10.1.1.2/24
                    location: 10.0.0.20;1;1   # chassis;card;port
                    link: link0

When ``ext`` is set the extension owns the connection, so ``transport`` is not
passed to ``snappi``: the two are mutually exclusive.

Licensing must be configured before ports are connected, otherwise port
assignment fails with ``Port Released (License Failed)``. By default that is
the responsibility of the IxNetwork API-server administrator. An OTG testbed
can instead request a one-time, pre-Snappi licensing update as described in
`IxNetwork licensing from an OTG testbed`_.

IxNetwork licensing from an OTG testbed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For an ``ext: ixnetwork`` connection, these optional keys use a short-lived
IxNetwork Tcl session to configure licensing before the native Snappi session
is created. Snappi continues to own all OTG configuration, traffic and
statistics operations.

.. code-block:: yaml

    devices:
        otg:
            type: tgn
            os: otg
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    transport: https
                    ip: 192.0.2.10
                    port: 443
                    ext: ixnetwork
                    ixnetwork_tcl_port: 8020
                    ixnetwork_version: '9.30'
                    ixia_license_server_ip:
                        - 198.51.100.10
                        - 198.51.100.11
                    ixnetwork_license_mode: subscription
                    ixnetwork_license_tier: tier2

``ixia_license_server_ip`` also accepts one server or a comma/semicolon-
delimited string. In a dynamic pyVXR testbed, set
``ixnetwork_tcl_port`` from the allocated ``tgn1_gui`` ``redir8020`` value;
it is distinct from the REST/OTG port.

The bridge requires ``ext: ixnetwork``, a real controller transport, a Tcl
port and an IxNetwork version. It reads back every requested setting and fails
the connection before Snappi starts if any operation fails. It never uses
``closeServerOnDisconnect``. Do not use these keys against shared controllers
unless the allocation exclusively owns the controller-wide license settings.

Testbed YAML
------------

Set ``os: otg`` so ``Genie`` abstraction resolves the plugin, and ``type: tgn``
so the ``Genie`` harness discovers the device as a traffic generator.

REST / HTTPS controller
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

    devices:
        otg:
            type: tgn
            os: otg
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    transport: https
                    ip: 192.0.2.100
                    port: 8443
                    verify_certificate: False  # opt out for self-signed labs
                    timeout: 30                # default

    topology:
        otg:
            interfaces:
                port1:
                    type: ethernet
                    ipv4: 10.1.1.2/24
                    link: link_to_dut
                port2:
                    type: ethernet
                    ipv4: 10.1.2.2/24
                    link: link_from_dut

Every interface declared in ``topology`` is registered as an OTG port on
connect, using the interface ``location`` if present, otherwise its ``link``
name. Interface addressing also drives receiving port inference, so
``check_traffic_loss`` reports Rx counters without any extra wiring.

gRPC controller
^^^^^^^^^^^^^^^

.. code-block:: yaml

    devices:
        otg:
            type: tgn
            os: otg
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    transport: grpc
                    location: "192.0.2.100:40051"

Hardware-free simulation
^^^^^^^^^^^^^^^^^^^^^^^^

``transport: mock`` runs an in-memory OTG simulator, so suites can be developed
and regression tested without a traffic generator and without ``snappi``.

Rate choices are preserved when configurations are serialized. The simulator
supports ``pps`` and fixed-frame ``bps``, ``kbps``, ``mbps`` and ``gbps``
rates. Bit-rate simulation divides the configured bits per second by eight
times the fixed frame size; physical-layer overhead is not simulated.
Live rate and size updates preserve accumulated counters.

Mock flow-rate and frame-size attributes support explicit ``dict``, ``json``
and ``yaml`` serialization encodings. Their ``serialize()`` methods retain
the existing dictionary default; unsupported encodings raise an error.

The simulator has no physical link speed, so applying a ``percentage`` rate
raises an explicit unsupported error. Such rates can still be represented in
the configuration model and used with a controller that supports them.
A PPS reference is reported only when PPS is the active rate choice; traffic
checks use measured transmit rate for other choices.

.. code-block:: yaml

    devices:
        otg:
            type: tgn
            os: otg
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    transport: mock
                    location: mock

Connection keys
---------------

.. list-table::
   :header-rows: 1

   * - Key
     - Description
   * - ``transport``
     - ``mock``, ``http``, ``https`` or ``grpc``; defaults to ``mock``.
   * - ``platform`` (device key)
     - Selects the OTG backend. ``ixia``, or omitted, is a controller that
       speaks OTG natively, or IxNetwork with ``ext: ixnetwork``; ``ixia``
       also defines the IxNetwork-only ``ixianative`` methods, which report
       what to use instead (see `Migrating from ixianative`_). Another value
       needs the package that serves it; see `Extending the OTG plugin`_.
   * - ``location``
     - Controller endpoint. When omitted it is built from ``protocol``,
       ``ip`` and ``port``.
   * - ``ip``
     - Controller address. Defaults to ``127.0.0.1``.
   * - ``port``
     - Controller port. Defaults to ``8443`` for REST and ``40051`` for gRPC.
   * - ``protocol``
     - URL scheme for REST. Defaults to ``https``.
   * - ``verify_certificate``
     - Verify the controller TLS certificate. Defaults to ``True``; set
       ``False`` for self-signed lab controllers.
   * - ``timeout``
     - Request timeout in seconds. Defaults to ``30``.
   * - ``ext``
     - Snappi extension driving a vendor backend, for example ``ixnetwork``;
       the extension owns the Snappi transport.
   * - ``ixia_license_server_ip``
     - Optional IxNetwork license server or servers; requires ``ext:
       ixnetwork`` and the Tcl keys below.
   * - ``ixnetwork_license_mode``
     - Optional IxNetwork licensing mode.
   * - ``ixnetwork_license_tier``
     - Optional IxNetwork licensing tier.
   * - ``ixnetwork_tcl_port``
     - Required with any IxNetwork licensing key; the controller Tcl port,
       distinct from ``port``.
   * - ``ixnetwork_version``
     - Required with any IxNetwork licensing key.

Port ``location`` is taken from the testbed interface, falling back to the
link name. For IxNetwork it must be ``chassis;card;port``.

Legacy compatibility mode
-------------------------

.. code-block:: python

    tgn = testbed.devices['otg']
    tgn.connect(via='tgn', alias='tgn')

    tgn.configure_ipv4_data_traffic(interface='port1',
                                    src_ip='10.1.1.2',
                                    dst_ip='10.1.2.2',
                                    l4_protocol='udp',
                                    transmit_mode='continuous',
                                    pps=1000)
    tgn.send_arp(wait_time=5)
    tgn.clear_statistics()
    tgn.start_traffic()
    tgn.check_traffic_loss(loss_tolerance=1, max_outage=5)
    tgn.stop_traffic()

``configure_ipv4_data_traffic`` and ``configure_ipv6_data_traffic`` return the
generated flow name, which can be passed back as ``traffic_streams`` to
``start_traffic``, ``stop_traffic`` and ``check_traffic_loss``.

Enforcing versus measuring
^^^^^^^^^^^^^^^^^^^^^^^^^^

``check_traffic_loss`` defaults to ``raise_on_loss=True``: a stream that breaks
``loss_tolerance``, ``max_outage`` or ``rate_tolerance`` on the final iteration
is logged at error level and raises ``GenieTgnError``. This is the mode to use
whenever the result should reflect the health of the traffic -- let the
exception propagate, or map it onto ``step.failed()``, so the section actually
fails.

Passing ``raise_on_loss=False`` turns the call into a measurement: the returned
per-stream data is the point, breaches are logged at info level, and nothing
raises. It is meant for a section that induces loss on purpose and then
computes something from it. A section that only ever calls with
``raise_on_loss=False`` cannot fail on traffic health, so pair it with an
enforcing call once traffic is expected to have recovered:

.. code-block:: python

    # deliberately induced outage -- measure it, do not fail on it
    data = tgn.check_traffic_loss(loss_tolerance=100, rate_tolerance=None,
                                  check_iteration=1, raise_on_loss=False)
    outage = data[-1]['stream'][flow]['Outage (seconds)']

    # traffic must be healthy again -- this one is allowed to fail
    tgn.clear_statistics(wait_time=10)
    tgn.check_traffic_loss(loss_tolerance=0.5, max_outage=1, check_iteration=3)

A flow that is not transmitting is not treated as a fault. A ``fixed_packets``
flow that finished before ``clear_statistics()`` baselined the counters reads
zero transmitted frames, and so does any stopped flow; neither is reported as
dead traffic. A flow that still reports itself as transmitting while sending
nothing is reported, which is the case the check exists for.

Receiving port inference
^^^^^^^^^^^^^^^^^^^^^^^^

OTG binds every flow to both a transmitting and a receiving port. The legacy
APIs only name the transmitting interface, so the receiving port is resolved in
order:

1. An explicit ``rx_interface``, ``dst_interface``, ``rx_port``, ``dst_port``,
   ``receiving_interface`` or ``rx_name`` keyword.
2. The testbed interface whose subnet contains ``dst_ip``.
3. The peer interface on the same device sharing the transmitting link.
4. The next configured port.
5. The transmitting port itself, as a single-port loopback.

Emulated endpoints and the next hop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``configure_ipv4_data_traffic`` and ``configure_ipv6_data_traffic`` emulate a
device for the source address on the transmitting port and, by default, one
for the destination address on the receiving port. The flow is then bound to
those device endpoints rather than to raw ports, which is what lets the traffic
generator resolve both MAC addresses by ARP or Neighbor Discovery. A routed
flow bound only to ports leaves with an unresolved destination MAC and the
device under test drops it.

Pass ``emulate_destination=False`` to bind the flow to ports instead, for
example when the destination is a real host beyond the traffic generator.

The next hop each emulated device resolves through is derived from the
testbed: the peer across the port's link, which is normally the device under
test. Override it with ``gateway=`` for the source and ``dst_gateway=`` for the
destination. If neither a link peer nor a directly connected destination is
available the plugin logs a warning, because ARP will not resolve.

.. note::

   Reading ``flow.tx_rx.port`` on a device-bound flow silently rewrites the
   flow to use ports, because selecting an OTG choice is what reading it does.
   Use ``tgn.translation_engine.flow_endpoints(flow)`` to inspect a flow's
   transmitting and receiving ports safely.

Clearing statistics
^^^^^^^^^^^^^^^^^^^

OTG counters are monotonic, so ``clear_statistics()`` records a baseline offset
rather than zeroing chassis registers. All subsequent statistics are reported
relative to that baseline.

Not every backend agrees: IxNetwork zeroes a flow's counters each time traffic
starts, while ixia-c keeps them monotonic. ``start_traffic()`` therefore
re-checks the baselines the moment traffic starts and lowers any that now
exceed their counter. Without that, a rerun whose counters restart and climb
back to the previous total would appear to have transmitted nothing.

Native declarative mode
-----------------------

.. code-block:: python

    tgn = testbed.devices['otg']
    tgn.connect(via='tgn', alias='tgn')

    config = tgn.new_config()

    config.ports.add(name='p1', location='localhost:5555')
    config.ports.add(name='p2', location='localhost:5556')

    flow = config.flows.add(name='f1')
    flow.tx_rx.port.tx_name = 'p1'
    flow.tx_rx.port.rx_name = 'p2'
    flow.packet.ethernet()
    flow.packet.ipv4()[-1].src.value = '10.1.1.2'
    flow.rate.pps = 1000
    flow.duration.fixed_packets.packets = 100
    flow.metrics.enable = True

    tgn.set_config(config)

    state = tgn.api.control_state()
    state.choice = state.TRAFFIC
    state.traffic.choice = state.traffic.FLOW_TRANSMIT
    state.traffic.flow_transmit.state = state.traffic.flow_transmit.START
    tgn.set_state(state)

    request = tgn.api.metrics_request()
    request.choice = request.FLOW
    for metric in tgn.get_metrics(request).flow_metrics:
        print(metric.name, metric.frames_tx, metric.frames_rx, metric.loss_percent)

``set_config()`` also accepts a dictionary or a JSON/YAML string, so a
configuration can be kept next to the test as data:

.. code-block:: python

    tgn.set_config(open('otg_config.yaml').read())

Native configuration lifecycle
------------------------------

``apply_configuration()`` is the lifecycle-oriented companion to
``set_config()``. It accepts a file path, OTG configuration object, mapping,
or JSON/YAML payload. Inline payloads are copied to the pyATS archive just as
file-based input is, which makes the complete controller input recoverable
from a run result.

With its default ``restart=True``, it stops an existing applied configuration,
pushes the replacement, resolves both IPv4 ARP and IPv6 neighbours represented
by the configuration, starts traffic, and records fresh statistics baselines.
Set ``restart=False`` only when a testcase deliberately owns those lifecycle
steps itself.

.. code-block:: python

    tgn.apply_configuration({
        'ports': [
            {'name': 'p1', 'location': '192.0.2.10;1;1'},
            {'name': 'p2', 'location': '192.0.2.10;1;2'},
        ],
        'flows': [{
            'name': 'reserved-address-flow',
            'tx_rx': {'choice': 'port',
                      'port': {'tx_name': 'p1', 'rx_name': 'p2'}},
            'rate': {'choice': 'pps', 'pps': '200'},
        }],
    }, wait_time=10)

``update_configuration()`` is intentionally narrower than a generic merge
patch. It changes explicit scalar properties on uniquely named OTG objects,
validates every requested name/property before changing any value, and rolls
the in-memory values back if the controller rejects a restarted push. Nested
objects and lists must be supplied through a full replacement instead.

.. code-block:: python

    tgn.update_configuration([
        {'name': 'ipv4-on-p1', 'address': '192.0.2.2'},
        {'name': 'peer-route', 'as_number': 64512},
    ])

For the controller's in-place flow changes, use
``update_traffic_profile(traffic_streams=['reserved-address-flow'],
rate=500, size=256)``. Routes can be changed without restarting protocol
emulation through ``set_route_state(route_names=['peer-route'],
state='withdraw')`` (or ``'advertise'``).

Blitz datafiles
---------------

Blitz can call the OTG plugin through its existing generic ``tgn`` action;
no OTG-specific Blitz action is required. Connect the ``tgn`` alias once,
then pass the native configuration mapping directly to
``apply_configuration``. The configuration remains a full replacement, while
``update_configuration`` accepts only explicit named scalar updates.

.. code-block:: yaml

    TriggerOtgNativeConfiguration:
      source:
        pkg: genie.libs.sdk
        class: triggers.blitz.blitz.Blitz
      devices: [otg]
      test_sections:
        - configure_and_verify:
            - tgn:
                device: otg
                function: connect
            - tgn:
                device: otg
                function: apply_configuration
                arguments:
                  wait_time: 10
                  configuration:
                    ports:
                      - name: p1
                        location: 192.0.2.10;1;1
                      - name: p2
                        location: 192.0.2.10;1;2
                    flows:
                      - name: reserved-address-flow
                        tx_rx:
                          choice: port
                          port:
                            tx_name: p1
                            rx_name: p2
                        rate:
                          choice: pps
                          pps: '200'
            - tgn:
                device: otg
                function: check_traffic_loss
                arguments:
                  traffic_streams: [reserved-address-flow]
                  loss_tolerance: 1
                  check_iteration: 1

The generic action returns the plugin method's native result. Standard metric
dictionaries can be saved directly. When comparing traffic profiles, save each
``create_traffic_streams_table`` result and pass each whole
``%VARIABLES{...}`` value to ``compare_traffic_profile`` so Blitz retains the
``PrettyTable`` objects.

Genie harness
-------------

The plugin implements the traffic generator API that ``Genie`` harness drives,
so an ``os: otg`` device can be used wherever an Ixia device is used today.
``tgn_enable`` and the other ``tgn_*`` job arguments behave as documented in
the harness traffic section.

Two behaviours differ from Ixia, because OTG models them differently:

* ``assign_ixia_ports()`` is a no-op. OTG binds ports to their test locations
  declaratively as part of the configuration.
* ``create_genie_statistics_view()`` enables per-flow metrics rather than
  building a custom statistics view - OTG reports per-stream loss natively.

``create_traffic_streams_table()`` returns a profile using the same column
headers as the Ixia plugins, so golden profiles remain comparable.

Run artifacts
^^^^^^^^^^^^^

``load_configuration()`` keeps a copy of the configuration it loaded in the
pyATS runtime directory, which means it is collected into the archive that
``pyats run job --archive-dir`` produces. A result therefore carries the
traffic configuration that produced it::

    Archived OTG configuration as '/path/to/runinfo/tgn1_otg_config.json'

The copy is named after the device that loaded it, so several traffic
generators reading the same file do not overwrite each other. It is taken
before the configuration is pushed, so a configuration the controller rejects
is archived too - that is the one worth reading afterwards.

Nothing is written when the script runs outside ``easypy``, where there is no
archive and no runtime directory. Failing to archive is logged as a warning
and never fails a run.

Generated configuration, capture and statistics snapshot filenames percent-encode
device names, port names and base names. For example, port ``Ethernet1/1`` becomes
``Ethernet1%2F1`` in a filename. These names remain single filename components,
and the resolved output path must stay inside the selected artifact directory;
an existing symlink pointing outside that directory is rejected. Explicit
destination paths passed to ``save_capture`` or ``save_configuration`` are
preserved. ``save_packet_capture_file`` also accepts an explicit destination
directory, with its generated filename kept inside that directory.
``export_packet_capture_file`` treats ``dest_file`` as a filename inside the
runtime directory, and ``save_statistics_snapshot_csv`` treats ``csv_file_name``
as a base name inside its selected directory. Path separators in these names
are encoded; for example, ``../snapshot`` produces ``..%2Fsnapshot.csv``.

Supported APIs
--------------

.. csv-table:: Legacy traffic generator APIs
    :header: "API", "Notes"

    "``connect`` / ``disconnect``", "Idempotent; ``disconnect`` stops traffic first"
    "``configure_ipv4_data_traffic``", "Ethernet / IPv4 / TCP or UDP flow"
    "``configure_ipv6_data_traffic``", "Ethernet / IPv6 / TCP or UDP flow"
    "``configure_dhcpv4_request``", "RFC 2131 BOOTP / DHCP Request payload"
    "``send_arp`` / ``send_ns``", "Starts protocol emulation on emulated devices"
    "``send_arp_request``", "Raw ARP Request flow, no protocol emulation"
    "``start_traffic`` / ``stop_traffic``", "Optionally scoped to named streams"
    "``clear_traffic``", "Removes all flows"
    "``clear_statistics``", "Records counter baselines"
    "``check_traffic_loss``", "Loss, outage and rate validation"
    "``get_stats``", "``Port Statistics`` or ``Flow Statistics``"

.. csv-table:: Genie harness APIs
    :header: "API", "Notes"

    "``load_configuration``", "Loads an OTG JSON or YAML configuration file"
    "``apply_configuration``", "Archive and apply a file/object/mapping/payload; optional full restart lifecycle"
    "``update_configuration``", "Validated named scalar updates; no implicit recursive merge"
    "``update_traffic_profile``", "Live per-flow rate/frame-size update"
    "``set_route_state``", "Advertise or withdraw named emulated routes"
    "``remove_configuration``", "Pushes an empty configuration"
    "``apply_traffic``", "Commits pending configuration"
    "``assign_ixia_ports``", "No-op"
    "``start_all_protocols`` / ``stop_all_protocols``", "Protocol emulation control"
    "``get_traffic_stream_names``", "Configured flow names"
    "``generate_traffic_streams``", "Validates and commits named streams"
    "``create_genie_statistics_view``", "Enables per-flow metrics"
    "``get_current_packet_rate`` / ``get_reference_packet_rate``", "Per-flow transmit rates"
    "``create_traffic_streams_table``", "Traffic profile as a ``PrettyTable``"
    "``get_golden_profile`` / ``compare_traffic_profile``", "Profile comparison"

.. csv-table:: Emulated BGP and capture APIs
    :header: "API", "Notes"

    "``get_bgp_metrics``", "Session metrics keyed by OTG peer name"
    "``verify_bgp_sessions``", "Waits for sessions to be up or down, optionally for End-of-RIB"
    "``set_bgp_peer_state``", "Brings named peers up or down without a configuration push"
    "``start_capture`` / ``stop_capture``", "Per-port capture control; every port by default"
    "``save_capture``", "Writes a port's capture to a ``.pcap`` file"

Emulated BGP needs a controller that supports it; it is not simulated by
``transport: mock``.

With ``ext: ixnetwork``, the extension reports BGP metrics by device group.
The plugin returns them under the configured OTG peer names. Configure one
BGP peer of each address family per device and use device names that remain
distinct when lowercased; ambiguous groups raise ``GenieTgnError``. Session
verification waits for all requested peers to appear in the metrics before
checking their state.
Per-peer BGP state control is not implemented by this extension and raises
``GenieTgnError``. Use ``start_all_protocols`` or ``stop_all_protocols`` when
the intended change applies to every protocol on the controller.

.. csv-table:: IxiaNative call signatures
    :header: "API", "Notes"

    "``enable_data_packet_capture`` / ``disable_data_packet_capture``", "Per-port capture, named as ``'p1, p2'`` or a list"
    "``enable_control_packet_capture`` / ``disable_control_packet_capture``", "The same capture; OTG does not split hardware from software"
    "``start_packet_capture`` / ``stop_packet_capture``", "Capture control, with an optional capture time"
    "``get_packet_capture_count`` / ``get_packet_capture_data``", "Frame count and raw bytes of a port's capture"
    "``save_packet_capture_file`` / ``export_packet_capture_file``", "Writes and copies ``<port>_HW_<name>.pcap`` or ``_SW_``"
    "``set_packet_rate`` / ``set_line_rate`` / ``set_layer2_bit_rate``", "Sets the matching OTG rate choice on a flow"
    "``get_packet_rate`` / ``get_line_rate`` / ``get_layer2_bit_rate``", "Reads the configured rate back"
    "``set_packet_size_fixed`` / ``get_packet_size``", "Fixed frame size of a flow"
    "``start_traffic_stream`` / ``stop_traffic_stream``", "One stream, optionally verifying it transmits"
    "``get_flow_group_names`` / ``start_flow_group`` / ``stop_flow_group``", "A stream is its own flow group"
    "``check_flow_groups_loss`` / ``check_ecmp_traffic_loss``", "Loss validation over the flows of the named streams"
    "``get_all_statistics_views``", "The view names this plugin serves"
    "``get_flow_statistics_data`` / ``get_traffic_items_statistics_data``", "One field of one stream"
    "``create_flow_statistics_table`` / ``get_flow_statistics_table``", "Flow statistics as a ``PrettyTable``, optionally exported as CSV"
    "``get_traffic_item_statistics_table`` / ``get_traffic_items_from_genie_view``", "Per-traffic-item statistics and the names behind a profile"
    "``save_statistics_snapshot_csv``", "Writes a view to CSV, on the host running the job"
    "``save_configuration``", "Writes the OTG configuration as JSON"
    "``regenerate_all_traffic_items``", "Commits the configured streams"
    "``get_traffic_attribute``", "``state`` and ``isTrafficRunning``"

These carry the ``ixianative`` names and signatures and are implemented once,
so every OTG backend answers them. See `Migrating from ixianative`_.

.. _Migrating from ixianative:

Migrating from ixianative
-------------------------

``platform: ixia`` answers to the ``ixianative`` method names over OTG, so a
script written for ``os: ixianative`` keeps its calls. What this buys is one
script against two generators: the same calls reach IxNetwork here and a
non-IxNetwork backend through its own ``platform``, because they are
implemented once on the OTG plugin rather than per backend.

What changes is the testbed and the traffic configuration. The device selects
the plugin with ``os`` and ``platform``, and its connection becomes the OTG one
described in `Driving IxNetwork`_:

.. code-block:: yaml

    devices:
        ixia:
            type: tgn
            os: otg            # was: ixianative
            platform: ixia     # new
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    transport: http
                    ip: 192.0.2.10     # was: ixnetwork_api_server_ip
                    port: 11009
                    ext: ixnetwork

Port locations move with the ports. ``ixianative`` takes ``ixia_chassis_ip``
and ``ixia_port_list`` on the connection; OTG takes each port from its topology
interface, as ``location: chassis;card;port``.

The traffic configuration moves to OTG too. ``load_configuration()`` takes an
OTG JSON or YAML file rather than an IxNetwork ``.ixncfg``, so the traffic a
suite loads has to be expressed in the OTG model; see
`Native configuration lifecycle`_.

``ixiarestpy`` has no separate migration: every method it defines is served
here.

What the method does on OTG
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A call keeps its name and its signature, and is answered the way OTG models
the thing it asks for. Where the two models differ, the OTG behaviour is:

.. csv-table:: Behaviour worth knowing before you migrate
    :header: "Calls", "On OTG"

    "``enable_data_packet_capture`` / ``enable_control_packet_capture``", "OTG captures a port without IxNetwork's hardware/software split, so both reach the same capture; ``pcap_type`` only selects the counter or file name reported"
    "``get_packet_capture_count``", "Counts frames in the returned file, which is ``pcapng`` when ``snappi_ixnetwork`` rewrites it"
    "``set_packet_rate`` / ``set_line_rate`` / ``set_layer2_bit_rate``", "Each sets the matching OTG rate choice; a flow carries one at a time, so reading a rate the flow does not use raises"
    "``get_flow_group_names`` / ``start_flow_group`` / ``stop_flow_group``", "OTG has no subdivision of a stream, so a stream is its own flow group"
    "``check_flow_groups_loss``", "``check_traffic_loss`` over the flows; the ``csv_windows_path`` and ``csv_file_name`` arguments are accepted and unused, since the numbers come from the metrics"
    "``save_statistics_snapshot_csv``", "Writes the view as CSV from the metrics, on the host running the job rather than on the IxNetwork client"
    "``get_traffic_attribute``", "Serves ``state`` and ``isTrafficRunning`` from the flows' own transmit state; the rest of the configuration is read with ``get_config()``"

Rate and fixed-size setters preserve an already-running flow. With
``start_traffic=True``, they start a stopped flow and wait for the requested
settling time; they do not issue another START for a running flow.
``start_traffic_stream(check_stream=True)`` requires current started state
and advancing transmit counters. Frames sent before the call do not prove
that the stream restarted.

What IxNetwork keeps to itself
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The rest of the ``ixianative`` surface hands back IxNetwork objects -
vports, traffic items, flow groups, Quick Flow Groups and QuickTest results -
or configures the chassis directly. OTG describes a traffic generator by
configuration and metrics and has no objects to return, so these are defined
but raise a ``GenieTgnError`` naming the IxNetwork construct and what to use
instead:

.. csv-table:: Not available on OTG
    :header: "Area", "Methods", "Instead"

    "IxNetwork object model", "``find_traffic_stream_object``, ``get_traffic_stream_objects``, ``get_traffic_stream_attribute``, ``find_flow_group_object``, ``get_flow_group_objects``, ``get_flow_group_attribute``, ``find_flow_statistics_page_obj``, ``find_traffic_item_statistics_page_obj``", "Address a stream by name; read the configuration with ``get_config()`` and the counters with ``get_stats()``"
    "Quick Flow Groups", "``get_quick_flow_group_names``, ``get_quick_flow_group_objects``, ``find_quick_flow_group_object``, ``get_quick_flow_group_attribute``, ``start_quick_flow_group``, ``stop_quick_flow_group``", "Configure the stream and drive it with ``start_traffic_stream()``"
    "QuickTest", "``find_quicktest_object``, ``load_quicktest_configuration``, ``execute_quicktest``, ``get_quicktest_results_attribute``, ``generate_export_quicktest_report``", "Drive the RFC procedure from the script, over the OTG flows"
    "Chassis, vports and layer 1", "``add_chassis``, ``get_vports``, ``get_ixia_virtual_port``, ``get_ixia_virtual_port_attribute``, ``get_ixia_virtual_port_capture``, ``set_ixia_virtual_ports``, ``enable_vlan_on_interface``, ``change_l1config_media``, ``configure_autonegotiate``", "Declare ports, their locations and their layer 1 settings in the configuration"
    "Traffic item construction", "``create_l2_traffic_stream``, ``create_l3_traffic_stream``, ``enable_flow_tracking_filter``", "``apply_configuration()``, or ``configure_ipv4_data_traffic()`` in `Legacy compatibility mode`_; OTG reports per-flow metrics without a tracking filter"

A suite that needs one of these is using IxNetwork rather than a traffic
generator, and stays on ``os: ixianative``.

.. _Extending the OTG plugin:

Extending the OTG plugin
------------------------

A traffic generator that does not speak OTG can still be driven through this
plugin, by a separate package that translates the model into whatever the
generator understands. A testbed then selects it with the device ``platform``,
and the suite keeps using ``class: genie.trafficgen.TrafficGen`` and the same
OTG configuration.

Such a package declares an abstraction package of its own, mirroring the token
layout of ``genie.trafficgen``, and registers it under the
``genie.trafficgen`` entry point:

.. code-block:: python

    # setup.py of the extension package
    entry_points={
        'genie.trafficgen': ['mylib = mylib.trafficgen'],
    }

Its layout adds a ``platform`` token below ``os: otg``:

.. code-block:: text

    mylib/trafficgen/__init__.py                 declare_package()
    mylib/trafficgen/otg/__init__.py             declare_token(os='otg')
    mylib/trafficgen/otg/mygen/__init__.py       declare_token(platform='mygen')
    mylib/trafficgen/otg/mygen/implementation.py class MyGen(Otg)

Every discovered package is merged into one abstraction tree, in which a later
package supersedes the nodes it shares with an earlier one. So the extension
must re-export the classes of the nodes it shares - its package root and its
``os: otg`` module - or a device that asks for plain OTG stops resolving:

.. code-block:: python

    # mylib/trafficgen/__init__.py
    from genie import abstract
    abstract.declare_package()
    from genie.trafficgen.trafficgen import TrafficGen  # noqa

    # mylib/trafficgen/otg/__init__.py
    from genie import abstract
    abstract.declare_token(os='otg')
    from genie.trafficgen.otg.implementation import Otg as TrafficGen  # noqa

A package that cannot be imported, learnt or merged is skipped with a warning,
so one broken extension does not take down every traffic generator connection
in a run. Because discovery reads entry points, an extension is only found
once it is installed - ``pip install`` or ``pip install -e`` - not by being
placed on ``PYTHONPATH``.

The backend itself subclasses ``Otg``, declares the ``platform`` it serves and
overrides only what its generator does differently:

.. code-block:: python

    from genie.trafficgen.otg.implementation import Otg

    class MyGen(Otg):
        SUPPORTED_PLATFORMS = ('mygen',)
        SUPPORTED_TRANSPORTS = ('ssh',)
        DEFAULT_TRANSPORT = 'ssh'
        USES_TEST_PORTS = False

        def _create_api(self):
            return MyGenApi(device=self.device)

``Otg`` rejects a ``platform`` it does not serve, naming the entry point, so a
testbed that asks for a backend whose package is missing fails at connect with
an explanation rather than falling back to a controller that is not there.

.. list-table:: Backend hooks
   :header-rows: 1

   * - Hook
     - Called from
   * - ``_validate_connection_options()``
     - ``__init__``, to reject keys the backend cannot honour
   * - ``_default_location()``
     - ``__init__``, when the testbed names no ``location``
   * - ``_create_api()``
     - ``connect()``, for every transport other than ``mock``
   * - ``_close_api()``
     - ``disconnect()``, after traffic has been stopped
   * - ``_deserialize_config()``
     - ``set_config()`` and ``apply_configuration()``
   * - ``_resolve_configuration_source()``
     - ``load_configuration()`` and ``apply_configuration()``, for references
       that are not local file paths
   * - ``_traffic_operation_is_noop()``
     - ``start_traffic()`` and ``check_traffic_loss()``
   * - ``_check_update_supported()``
     - ``update_configuration()``
   * - ``_default_route_names()``
     - ``set_route_state()``, when given no names
   * - ``_bgp_peer_names()``
     - the emulated BGP helpers

``send_arp()``, ``send_ns()``, ``start_all_protocols()`` and
``create_genie_statistics_view()`` are overridden directly when a backend
drives them differently.
