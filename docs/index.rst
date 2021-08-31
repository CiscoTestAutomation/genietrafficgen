Genie Trafficgen
================

Packets! As with any thorough testing, it's sometimes imperative to execute
tests with actual traffic flowing through devices. ``Genie`` can connect to
traffic generator (TGN) devices within a `testbed` topology.

This section provides an overview on how to connect to a traffic generator (TGN)
`device` and perform actions on those devices using ``Genie``.

We recommend reading through these sections in order, to help understand all
concepts associated with traffic generators within ``Genie``.

Genie currently supports the following traffic generator devices:

    1. Ixia Native - Using IxNetwork 7.50+
    2. Ixia via REST - Using IxNetwork 8.52+ and ixnetwork_restpy
    3. Pagent

.. toctree::
    :maxdepth: 1

    overview
    ixianative
    ixiarestpy
    pagent
    changelog/index
