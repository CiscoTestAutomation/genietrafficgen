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

The ``http``, ``https`` and ``grpc`` transports require the ``snappi`` SDK::

    pip install genie.trafficgen[otg]

``snappi`` is imported lazily, so it is only needed when you actually connect
to a controller. The ``mock`` transport has no extra dependency.

Driving IxNetwork
^^^^^^^^^^^^^^^^^

IxNetwork does not speak OTG natively. ``snappi`` reaches it through the
``snappi_ixnetwork`` extension, selected with the ``ext`` connection key::

    pip install snappi-ixnetwork

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

Licensing must already be configured on the IxNetwork API server, otherwise
port assignment fails with ``Port Released (License Failed)``. IxNetwork also
refuses license changes while ports are connected.

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

+-----------------------+----------------------------------------------------+
| Key                   | Description                                        |
+=======================+====================================================+
| ``transport``         | ``mock``, ``http``, ``https`` or ``grpc``.         |
|                       | Defaults to ``mock``.                              |
+-----------------------+----------------------------------------------------+
| ``location``          | Controller endpoint. When omitted it is built from |
|                       | ``protocol``, ``ip`` and ``port``.                 |
+-----------------------+----------------------------------------------------+
| ``ip``                | Controller address. Default ``127.0.0.1``.         |
+-----------------------+----------------------------------------------------+
| ``port``              | Controller port. Default ``8443`` for REST,        |
|                       | ``40051`` for gRPC.                                |
+-----------------------+----------------------------------------------------+
| ``protocol``          | URL scheme for REST. Default ``https``.            |
+-----------------------+----------------------------------------------------+
| ``verify_certificate``| Verify the controller TLS certificate.             |
|                       | Default ``True``; set ``False`` for self-signed    |
|                       | lab controllers.                                   |
+-----------------------+----------------------------------------------------+
| ``timeout``           | Request timeout in seconds. Default ``30``.        |
+-----------------------+----------------------------------------------------+
| ``ext``               | snappi extension driving a vendor backend, for     |
|                       | example ``ixnetwork``. Mutually exclusive with     |
|                       | ``transport``.                                     |
+-----------------------+----------------------------------------------------+

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
