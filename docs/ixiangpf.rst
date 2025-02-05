Ixia NGPF
=========

The `ixiangpf` module is the trafficgen implementation that uses `ixnetwork_ngpf`
to interface with Ixia devices.

The IxiaNgpf class can connect to Ixia traffic generator devices that are running
IxNetwork API server versions 7.50 or higher.

Usage:

.. code-block:: yaml

    devices:
        ixia8:
            type: tgn
            os: 'ixiangpf'
            connections:
                tgn:
                    class: genie.trafficgen.TrafficGen
                    ixnetwork_api_server_ip: 192.0.0.1 # Remote VM IP
                    ixnetwork_tcl_port: 8012
                    ixnetwork_version: '9.20'
                    ixia_chassis_ip: 1.1.1.1 # IxOS
                    ixia_license_server_ip: 192.0.0.1 # Remote VM IP
                    ixia_port_list: ['1/1', '1/2']

IxiaNgpf Class
==============

.. autoclass:: genie.trafficgen.ixiangpf.implementation.IxiaNgpf
    :members:
    :undoc-members:
    :show-inheritance:

