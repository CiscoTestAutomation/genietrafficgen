
pagent
===========

pagent is only available within Cisco

The `pagent` module is the trafficgen implementation that uses cli to interface with pagent devices.


``genie.trafficgen.pagent.Pagent`` class can connect to pagent

Usage:


.. code-block:: yaml

    devices:
        pagent:
            type: tgn
            os: pagent
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    ip: 10.1.1.1
                    port: 7100
                    protocol: telnet
