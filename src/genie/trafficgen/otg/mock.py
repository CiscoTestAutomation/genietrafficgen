'''
Hardware-free Open Traffic Generator (OTG) simulator.

Provides an in-memory object model mirroring the snappi/OTG schema, a stateful
traffic engine, and an API client that speaks either to that engine or to a
remote OTG controller over REST. Selected with ``transport: mock`` in the
testbed YAML, it lets pyATS suites exercise the full ``genie.trafficgen.otg``
surface with no traffic generator and no snappi install.

This module never registers itself as ``snappi``; when the real SDK is present
it is used instead for the http/https/grpc transports.
'''

import json
import time
import urllib.error
import urllib.request

import yaml

from genie.harness.exceptions import GenieTgnError

# Frame size assumed by the simulator when translating rates into byte counters.
SIMULATED_FRAME_SIZE = 128


# -----------------------------------------------------------------------------
# OTG object model
# -----------------------------------------------------------------------------

class OtgList(list):
    '''List exposing the ``add()`` constructor used by OTG collections.'''

    def __init__(self, item_factory=None):
        super().__init__()
        self._item_factory = item_factory

    def add(self, **kwargs):
        if self._item_factory is None:
            raise TypeError('No item factory provided for OtgList')
        item = self._item_factory(**kwargs)
        self.append(item)
        return item


class Pattern:
    '''Scalar field wrapper matching the OTG ``value``/``auto`` choice pattern.'''

    def __init__(self, value=None, choice='auto'):
        self._value = value
        self.choice = choice

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value
        self.choice = 'value'

    @property
    def auto(self):
        self.choice = 'auto'
        return self

    def __repr__(self):
        return 'Pattern(choice={!r}, value={!r})'.format(self.choice, self._value)


class Port:
    def __init__(self, name=None, location=None):
        self.name = str(name) if name is not None else None
        self.location = str(location) if location is not None else None

    def to_dict(self):
        return {'name': self.name, 'location': self.location}


class Ipv4Address:
    def __init__(self, name=None, address=None, gateway=None, prefix=24):
        self.name = str(name) if name else None
        self.address = str(address) if address else None
        self.gateway = str(gateway) if gateway else '0.0.0.0'
        self.prefix = int(prefix) if prefix is not None else 24

    def to_dict(self):
        return {'name': self.name, 'address': self.address,
                'gateway': self.gateway, 'prefix': self.prefix}


class Ipv6Address:
    def __init__(self, name=None, address=None, gateway=None, prefix=64):
        self.name = str(name) if name else None
        self.address = str(address) if address else None
        self.gateway = str(gateway) if gateway else '::'
        self.prefix = int(prefix) if prefix is not None else 64

    def to_dict(self):
        return {'name': self.name, 'address': self.address,
                'gateway': self.gateway, 'prefix': self.prefix}


class EthernetConnection:
    '''Binds an emulated ethernet interface to a port, lag or vxlan tunnel.'''

    def __init__(self):
        self.choice = 'port_name'
        self.port_name = None
        self.lag_name = None
        self.vxlan_name = None

    def to_dict(self):
        return {'choice': self.choice, 'port_name': self.port_name}


class Ethernet:
    def __init__(self, name=None, mac=None, mtu=1500):
        self.name = str(name) if name else None
        self.mac = str(mac) if mac else None
        self.mtu = int(mtu) if mtu is not None else 1500
        self.connection = EthernetConnection()
        self.ipv4_addresses = OtgList(Ipv4Address)
        self.ipv6_addresses = OtgList(Ipv6Address)

    def to_dict(self):
        return {
            'name': self.name,
            'mac': self.mac,
            'mtu': self.mtu,
            'connection': self.connection.to_dict(),
            'ipv4_addresses': [a.to_dict() for a in self.ipv4_addresses],
            'ipv6_addresses': [a.to_dict() for a in self.ipv6_addresses],
        }


class Device:
    def __init__(self, name=None):
        self.name = str(name) if name else None
        self.ethernets = OtgList(Ethernet)

    def to_dict(self):
        return {'name': self.name,
                'ethernets': [e.to_dict() for e in self.ethernets]}


class EthernetHeader:
    def __init__(self):
        self.src = Pattern('00:00:01:00:00:01')
        self.dst = Pattern('00:00:02:00:00:02')
        self.ether_type = Pattern(0x0800)

    def to_dict(self):
        return {'choice': 'ethernet',
                'ethernet': {'src': self.src.value, 'dst': self.dst.value,
                             'ether_type': self.ether_type.value}}


class Ipv4Header:
    def __init__(self):
        self.src = Pattern('192.0.2.1')
        self.dst = Pattern('192.0.2.2')
        self.protocol = Pattern(4)

    def to_dict(self):
        return {'choice': 'ipv4',
                'ipv4': {'src': self.src.value, 'dst': self.dst.value,
                         'protocol': self.protocol.value}}


class Ipv6Header:
    def __init__(self):
        self.src = Pattern('2001:db8::1')
        self.dst = Pattern('2001:db8::2')
        self.next_header = Pattern(58)

    def to_dict(self):
        return {'choice': 'ipv6',
                'ipv6': {'src': self.src.value, 'dst': self.dst.value,
                         'next_header': self.next_header.value}}


class TcpHeader:
    def __init__(self):
        self.src_port = Pattern(5000)
        self.dst_port = Pattern(5001)

    def to_dict(self):
        return {'choice': 'tcp',
                'tcp': {'src_port': self.src_port.value,
                        'dst_port': self.dst_port.value}}


class UdpHeader:
    def __init__(self):
        self.src_port = Pattern(5000)
        self.dst_port = Pattern(5001)

    def to_dict(self):
        return {'choice': 'udp',
                'udp': {'src_port': self.src_port.value,
                        'dst_port': self.dst_port.value}}


class ArpHeader:
    def __init__(self):
        self.hardware_type = Pattern(1)
        self.protocol_type = Pattern(0x0800)
        self.hardware_length = Pattern(6)
        self.protocol_length = Pattern(4)
        self.operation = Pattern(1)
        self.src_hardware_addr = Pattern('00:00:01:00:00:01')
        self.src_protocol_addr = Pattern('192.0.2.1')
        self.dst_hardware_addr = Pattern('00:00:00:00:00:00')
        self.dst_protocol_addr = Pattern('192.0.2.2')

    def to_dict(self):
        return {
            'choice': 'arp',
            'arp': {
                'hardware_type': self.hardware_type.value,
                'protocol_type': self.protocol_type.value,
                'hardware_length': self.hardware_length.value,
                'protocol_length': self.protocol_length.value,
                'operation': self.operation.value,
                'src_hardware_addr': self.src_hardware_addr.value,
                'src_protocol_addr': self.src_protocol_addr.value,
                'dst_hardware_addr': self.dst_hardware_addr.value,
                'dst_protocol_addr': self.dst_protocol_addr.value,
            },
        }


class CustomHeader:
    def __init__(self):
        self.bytes = ''

    def to_dict(self):
        return {'choice': 'custom', 'custom': {'bytes': self.bytes}}


class PacketHeaders(list):
    '''Header stack whose builders append and return the stack, as OTG does.'''

    _BUILDERS = {
        'ethernet': EthernetHeader,
        'ipv4': Ipv4Header,
        'ipv6': Ipv6Header,
        'tcp': TcpHeader,
        'udp': UdpHeader,
        'arp': ArpHeader,
        'custom': CustomHeader,
    }

    def add(self, item=None):
        if item is not None:
            self.append(item)
            return item
        return self[-1] if self else None

    def _append_header(self, kind):
        self.append(self._BUILDERS[kind]())
        return self

    def ethernet(self):
        return self._append_header('ethernet')

    def ipv4(self):
        return self._append_header('ipv4')

    def ipv6(self):
        return self._append_header('ipv6')

    def tcp(self):
        return self._append_header('tcp')

    def udp(self):
        return self._append_header('udp')

    def arp(self):
        return self._append_header('arp')

    def custom(self):
        return self._append_header('custom')

    def to_dict(self):
        return [h.to_dict() for h in self]


class FlowPort:
    def __init__(self):
        self.tx_name = None
        self.rx_names = []

    @property
    def rx_name(self):
        '''Deprecated in OTG in favour of rx_names; kept for compatibility.'''
        return self.rx_names[0] if self.rx_names else None

    @rx_name.setter
    def rx_name(self, value):
        self.rx_names = [value] if value else []

    def to_dict(self):
        return {'tx_name': self.tx_name, 'rx_names': list(self.rx_names)}


class FlowDevice:
    MESH = 'mesh'
    ONE_TO_ONE = 'one_to_one'

    def __init__(self):
        self.tx_names = []
        self.rx_names = []
        self.mode = self.ONE_TO_ONE

    def to_dict(self):
        return {'tx_names': list(self.tx_names),
                'rx_names': list(self.rx_names),
                'mode': self.mode}


class TxRx:
    PORT = 'port'
    DEVICE = 'device'

    def __init__(self):
        self.choice = self.PORT
        self._port = FlowPort()
        self._device = FlowDevice()

    @property
    def port(self):
        self.choice = self.PORT
        return self._port

    @property
    def device(self):
        self.choice = self.DEVICE
        return self._device

    def to_dict(self):
        if self.choice == self.DEVICE:
            return {'choice': self.choice, 'device': self._device.to_dict()}
        return {'choice': self.choice, 'port': self._port.to_dict()}


class FlowRate:
    def __init__(self):
        self.pps = 100

    def to_dict(self):
        return {'choice': 'pps', 'pps': self.pps}


class FixedPackets:
    def __init__(self):
        self.packets = 1

    def to_dict(self):
        return {'packets': self.packets}


class Continuous:
    def __init__(self):
        self.gap = 12

    def to_dict(self):
        return {'gap': self.gap}


class Burst:
    def __init__(self):
        self.packets = 1
        self.gap = 12

    def to_dict(self):
        return {'packets': self.packets, 'gap': self.gap}


class FlowDuration:
    def __init__(self):
        self.fixed_packets = FixedPackets()
        self.continuous = Continuous()
        self.burst = Burst()
        self.choice = 'continuous'

    def to_dict(self):
        return {
            'choice': self.choice,
            'fixed_packets': self.fixed_packets.to_dict(),
            'continuous': self.continuous.to_dict(),
            'burst': self.burst.to_dict(),
        }


class FlowMetricsConfig:
    def __init__(self):
        self.enable = True
        self.loss = True

    def to_dict(self):
        return {'enable': self.enable, 'loss': self.loss}


class Flow:
    def __init__(self, name=None):
        self.name = str(name) if name else None
        self.tx_rx = TxRx()
        self.packet = PacketHeaders()
        self.rate = FlowRate()
        self.duration = FlowDuration()
        self.metrics = FlowMetricsConfig()

    def to_dict(self):
        return {
            'name': self.name,
            'tx_rx': self.tx_rx.to_dict(),
            'packet': self.packet.to_dict(),
            'rate': self.rate.to_dict(),
            'duration': self.duration.to_dict(),
            'metrics': self.metrics.to_dict(),
        }


class Config:
    def __init__(self):
        self.ports = OtgList(Port)
        self.devices = OtgList(Device)
        self.flows = OtgList(Flow)

    def to_dict(self):
        return {
            'ports': [p.to_dict() for p in self.ports],
            'devices': [d.to_dict() for d in self.devices],
            'flows': [f.to_dict() for f in self.flows],
        }

    def serialize(self, encoding='json'):
        data = self.to_dict()
        if str(encoding).lower() in ('yaml', 'yml'):
            return yaml.safe_dump(data, default_flow_style=False)
        return json.dumps(data, indent=2)

    def deserialize(self, content):
        if isinstance(content, dict):
            data = content
        elif isinstance(content, (bytes, bytearray)):
            data = yaml.safe_load(content.decode('utf-8'))
        elif isinstance(content, str):
            # YAML is a JSON superset, so one loader covers both encodings.
            data = yaml.safe_load(content)
        else:
            raise GenieTgnError(
                'Cannot deserialize OTG configuration of type {}'.format(
                    type(content).__name__))

        if not isinstance(data, dict):
            raise GenieTgnError('OTG configuration must deserialize to a mapping')

        self.ports.clear()
        self.devices.clear()
        self.flows.clear()

        for port in data.get('ports') or []:
            self.ports.add(name=port.get('name'), location=port.get('location'))

        for device in data.get('devices') or []:
            dev = self.devices.add(name=device.get('name'))
            for eth_data in device.get('ethernets') or []:
                eth = dev.ethernets.add(name=eth_data.get('name'),
                                        mac=eth_data.get('mac'),
                                        mtu=eth_data.get('mtu', 1500))
                eth.connection.port_name = \
                    (eth_data.get('connection') or {}).get('port_name')
                for ip4 in eth_data.get('ipv4_addresses') or []:
                    eth.ipv4_addresses.add(name=ip4.get('name'),
                                           address=ip4.get('address'),
                                           gateway=ip4.get('gateway'),
                                           prefix=ip4.get('prefix', 24))
                for ip6 in eth_data.get('ipv6_addresses') or []:
                    eth.ipv6_addresses.add(name=ip6.get('name'),
                                           address=ip6.get('address'),
                                           gateway=ip6.get('gateway'),
                                           prefix=ip6.get('prefix', 64))

        for flow_data in data.get('flows') or []:
            self._deserialize_flow(flow_data)

        return self

    def _deserialize_flow(self, flow_data):
        flow = self.flows.add(name=flow_data.get('name'))

        tx_rx = flow_data.get('tx_rx') or {}
        if tx_rx.get('choice') == TxRx.DEVICE:
            device = tx_rx.get('device') or {}
            flow.tx_rx.device.tx_names = list(device.get('tx_names') or [])
            flow.tx_rx.device.rx_names = list(device.get('rx_names') or [])
        else:
            port = tx_rx.get('port') or {}
            flow.tx_rx.port.tx_name = port.get('tx_name')
            if port.get('rx_names'):
                flow.tx_rx.port.rx_names = list(port['rx_names'])
            else:
                flow.tx_rx.port.rx_name = port.get('rx_name')

        rate = flow_data.get('rate') or {}
        if 'pps' in rate:
            flow.rate.pps = rate['pps']

        duration = flow_data.get('duration') or {}
        if 'choice' in duration:
            flow.duration.choice = duration['choice']
        if 'fixed_packets' in duration:
            flow.duration.fixed_packets.packets = \
                duration['fixed_packets'].get('packets', 1)
        if 'continuous' in duration:
            flow.duration.continuous.gap = duration['continuous'].get('gap', 12)
        if 'burst' in duration:
            flow.duration.burst.packets = duration['burst'].get('packets', 1)

        metrics = flow_data.get('metrics') or {}
        if 'enable' in metrics:
            flow.metrics.enable = bool(metrics['enable'])
        if 'loss' in metrics:
            flow.metrics.loss = bool(metrics['loss'])

        for header in flow_data.get('packet') or []:
            choice = header.get('choice')
            if choice not in PacketHeaders._BUILDERS:
                continue
            getattr(flow.packet, choice)()
            for field, value in (header.get(choice) or {}).items():
                attr = getattr(flow.packet[-1], field, None)
                if isinstance(attr, Pattern):
                    attr.value = value
                elif attr is not None or field == 'bytes':
                    setattr(flow.packet[-1], field, value)

        return flow


class FlowTransmit:
    START = 'start'
    STOP = 'stop'

    def __init__(self):
        self.state = self.START
        self.flow_names = []

    def to_dict(self):
        return {'state': self.state, 'flow_names': list(self.flow_names)}


class TrafficControlState:
    FLOW_TRANSMIT = 'flow_transmit'

    def __init__(self):
        self.choice = self.FLOW_TRANSMIT
        self.flow_transmit = FlowTransmit()

    def to_dict(self):
        return {'choice': self.choice,
                'flow_transmit': self.flow_transmit.to_dict()}


class AllProtocol:
    START = 'start'
    STOP = 'stop'

    def __init__(self):
        self.state = self.START

    def to_dict(self):
        return {'state': self.state}


class ProtocolControlState:
    ALL = 'all'

    def __init__(self):
        self.choice = self.ALL
        self.all = AllProtocol()

    def to_dict(self):
        return {'choice': self.choice, 'all': self.all.to_dict()}


class PortLink:
    UP = 'up'
    DOWN = 'down'

    def __init__(self):
        self.port_names = []
        self.state = self.UP

    def to_dict(self):
        return {'port_names': list(self.port_names), 'state': self.state}


class PortControlState:
    LINK = 'link'

    def __init__(self):
        self.choice = self.LINK
        self.link = PortLink()

    def to_dict(self):
        return {'choice': self.choice, 'link': self.link.to_dict()}


class ControlState:
    TRAFFIC = 'traffic'
    PROTOCOL = 'protocol'
    PORT = 'port'

    def __init__(self):
        self.choice = self.TRAFFIC
        self.traffic = TrafficControlState()
        self.protocol = ProtocolControlState()
        self.port = PortControlState()

    def to_dict(self):
        return {'choice': self.choice,
                'traffic': self.traffic.to_dict(),
                'protocol': self.protocol.to_dict(),
                'port': self.port.to_dict()}


class FlowMetricsRequest:
    def __init__(self):
        self.flow_names = []

    def to_dict(self):
        return {'flow_names': list(self.flow_names)}


class PortMetricsRequest:
    def __init__(self):
        self.port_names = []

    def to_dict(self):
        return {'port_names': list(self.port_names)}


class MetricsRequest:
    FLOW = 'flow'
    PORT = 'port'

    def __init__(self):
        self.choice = self.FLOW
        self.flow = FlowMetricsRequest()
        self.port = PortMetricsRequest()

    def to_dict(self):
        return {'choice': self.choice, 'flow': self.flow.to_dict(),
                'port': self.port.to_dict()}


class FlowMetric:
    # Field names follow the OTG schema: the byte rates are tx_rate_bytes and
    # rx_rate_bytes, not bytes_tx_rate.
    def __init__(self, name, frames_tx=0, frames_rx=0, bytes_tx=0, bytes_rx=0,
                 frames_tx_rate=0.0, frames_rx_rate=0.0, tx_rate_bytes=0.0,
                 rx_rate_bytes=0.0, loss_percent=0.0, transmit='stopped'):
        self.name = str(name)
        self.frames_tx = int(frames_tx)
        self.frames_rx = int(frames_rx)
        self.bytes_tx = int(bytes_tx)
        self.bytes_rx = int(bytes_rx)
        self.frames_tx_rate = float(frames_tx_rate)
        self.frames_rx_rate = float(frames_rx_rate)
        self.tx_rate_bytes = float(tx_rate_bytes)
        self.rx_rate_bytes = float(rx_rate_bytes)
        self.loss_percent = float(loss_percent)
        self.transmit = str(transmit)

    def to_dict(self):
        return {
            'name': self.name,
            'frames_tx': self.frames_tx,
            'frames_rx': self.frames_rx,
            'bytes_tx': self.bytes_tx,
            'bytes_rx': self.bytes_rx,
            'frames_tx_rate': self.frames_tx_rate,
            'frames_rx_rate': self.frames_rx_rate,
            'tx_rate_bytes': self.tx_rate_bytes,
            'rx_rate_bytes': self.rx_rate_bytes,
            'loss_percent': self.loss_percent,
            'transmit': self.transmit,
        }


class PortMetric:
    def __init__(self, name, frames_tx=0, frames_rx=0, bytes_tx=0, bytes_rx=0,
                 frames_tx_rate=0.0, frames_rx_rate=0.0, tx_rate_bytes=0.0,
                 rx_rate_bytes=0.0, link='up'):
        self.name = str(name)
        self.frames_tx = int(frames_tx)
        self.frames_rx = int(frames_rx)
        self.bytes_tx = int(bytes_tx)
        self.bytes_rx = int(bytes_rx)
        self.frames_tx_rate = float(frames_tx_rate)
        self.frames_rx_rate = float(frames_rx_rate)
        self.tx_rate_bytes = float(tx_rate_bytes)
        self.rx_rate_bytes = float(rx_rate_bytes)
        self.link = str(link)

    def to_dict(self):
        return {
            'name': self.name,
            'frames_tx': self.frames_tx,
            'frames_rx': self.frames_rx,
            'bytes_tx': self.bytes_tx,
            'bytes_rx': self.bytes_rx,
            'frames_tx_rate': self.frames_tx_rate,
            'frames_rx_rate': self.frames_rx_rate,
            'tx_rate_bytes': self.tx_rate_bytes,
            'rx_rate_bytes': self.rx_rate_bytes,
            'link': self.link,
        }


class MetricsResponse:
    def __init__(self, flow_metrics=None, port_metrics=None):
        self.flow_metrics = flow_metrics or []
        self.port_metrics = port_metrics or []

    def to_dict(self):
        return {'flow_metrics': [m.to_dict() for m in self.flow_metrics],
                'port_metrics': [m.to_dict() for m in self.port_metrics]}


# -----------------------------------------------------------------------------
# Simulation engine
# -----------------------------------------------------------------------------

class MockOtgEngine:
    '''Stateful in-memory traffic generator.

    Simulates flow and port counters from configured rates and durations,
    injectable loss, link flaps, ARP/ND resolution, DHCPv4 lease allocation and
    hardware counter resets.
    '''

    def __init__(self):
        self._config = None
        self._ports = {}
        self._flows = {}
        self._devices = {}
        self._warnings = []
        self._dhcp_pool_next = 100
        self._pending_loss = {}
        self._pending_link = {}
        self._reset_on_start = False

    # -- configuration --------------------------------------------------------

    def set_config(self, config):
        self._config = config
        self._warnings = []

        declared_ports = {p.name for p in getattr(config, 'ports', []) if
                          getattr(p, 'name', None)}
        for flow in getattr(config, 'flows', []):
            tx_port, rx_port = self._flow_ports(config, flow)
            for label, port_name in (('tx', tx_port), ('rx', rx_port)):
                if port_name and port_name not in declared_ports:
                    self._warnings.append(
                        "Flow '{f}' references undeclared {d} port '{p}'".format(
                            f=flow.name, d=label, p=port_name))

        for port in config.ports:
            if port.name not in self._ports:
                self._ports[port.name] = {
                    'name': port.name,
                    'location': port.location,
                    'link': self._pending_link.get(port.name, 'up'),
                    'frames_tx': 0, 'frames_rx': 0,
                    'bytes_tx': 0, 'bytes_rx': 0,
                    'frames_tx_rate': 0.0, 'frames_rx_rate': 0.0,
                    'bytes_tx_rate': 0.0, 'bytes_rx_rate': 0.0,
                }

        for device in config.devices:
            self._devices.setdefault(device.name, {'name': device.name,
                                                   'arp_resolved': {},
                                                   'dhcp_lease': None})

        configured_flows = set()
        for flow in config.flows:
            configured_flows.add(flow.name)
            self._sync_flow(flow)

        # Flows removed from the config must stop reporting metrics.
        for stale in set(self._flows) - configured_flows:
            del self._flows[stale]

        self._recompute_port_counters()
        return {'status': 'success', 'warnings': list(self._warnings)}

    @staticmethod
    def _endpoint_port(config, names):
        '''Maps emulated IP endpoint names back to the port hosting them.'''
        wanted = set(names or [])
        for device in getattr(config, 'devices', []):
            for eth in device.ethernets:
                for address in list(eth.ipv4_addresses) + list(eth.ipv6_addresses):
                    if address.name in wanted:
                        return eth.connection.port_name
        return None

    def _flow_ports(self, config, flow):
        '''Returns the (tx, rx) ports a flow uses, whichever endpoint it binds.'''
        tx_rx = flow.tx_rx
        if tx_rx.choice == TxRx.DEVICE:
            return (self._endpoint_port(config, tx_rx.device.tx_names),
                    self._endpoint_port(config, tx_rx.device.rx_names))
        return tx_rx.port.tx_name, (tx_rx.port.rx_names[0]
                                    if tx_rx.port.rx_names else None)

    def _sync_flow(self, flow):
        rate_pps = getattr(getattr(flow, 'rate', None), 'pps', 100) or 100
        duration = getattr(flow, 'duration', None)
        duration_type = getattr(duration, 'choice', 'continuous')

        target_packets = None
        if duration_type == 'fixed_packets':
            target_packets = getattr(duration.fixed_packets, 'packets', 1)
        elif duration_type == 'burst':
            target_packets = getattr(duration.burst, 'packets', 1)

        pending = self._pending_loss.get(flow.name, {})
        state = self._flows.get(flow.name)

        if state is None:
            state = {
                'name': flow.name,
                'transmit': 'stopped',
                'start_time': None,
                'stop_time': None,
                'frames_tx': 0, 'frames_rx': 0,
                'bytes_tx': 0, 'bytes_rx': 0,
                'accumulated_frames_tx': 0, 'accumulated_bytes_tx': 0,
                'accumulated_frames_rx': 0, 'accumulated_bytes_rx': 0,
                'frames_tx_rate': 0.0, 'frames_rx_rate': 0.0,
                'bytes_tx_rate': 0.0, 'bytes_rx_rate': 0.0,
                'loss_pct': float(pending.get('loss_pct') or 0.0),
                'loss_frames': int(pending.get('loss_frames') or 0),
                'frame_size': SIMULATED_FRAME_SIZE,
            }
            self._flows[flow.name] = state
        else:
            if pending.get('loss_pct') is not None:
                state['loss_pct'] = float(pending['loss_pct'])
            if pending.get('loss_frames') is not None:
                state['loss_frames'] = int(pending['loss_frames'])

        state['tx_port'], state['rx_port'] = self._flow_ports(self._config, flow)
        state['pps'] = float(rate_pps)
        state['duration_type'] = duration_type
        state['target_packets'] = target_packets

    def get_config(self):
        return self._config

    # -- control state --------------------------------------------------------

    def set_control_state(self, control_state):
        choice = getattr(control_state, 'choice', None)

        if choice == ControlState.TRAFFIC:
            self._apply_traffic_state(control_state.traffic)
        elif choice == ControlState.PROTOCOL:
            protocol = control_state.protocol
            if getattr(protocol, 'all', None) and \
                    protocol.all.state == AllProtocol.START:
                self._resolve_arp_all()
        elif choice == ControlState.PORT:
            link = getattr(control_state.port, 'link', None)
            if link:
                for port_name in link.port_names:
                    self.set_port_link(port_name, link.state)

        return {'status': 'success'}

    def _apply_traffic_state(self, traffic):
        if getattr(traffic, 'choice', None) != TrafficControlState.FLOW_TRANSMIT:
            return

        transmit = traffic.flow_transmit
        flow_names = transmit.flow_names or list(self._flows)

        for name in flow_names:
            flow = self._flows.get(name)
            if flow is None:
                continue
            if transmit.state == FlowTransmit.START:
                if self._reset_on_start:
                    for key in ('frames_tx', 'frames_rx', 'bytes_tx', 'bytes_rx',
                                'accumulated_frames_tx', 'accumulated_bytes_tx',
                                'accumulated_frames_rx', 'accumulated_bytes_rx'):
                        flow[key] = 0
                flow['transmit'] = 'started'
                flow['start_time'] = time.time()
                flow['stop_time'] = None
                self._simulate_flow(name)
            elif transmit.state == FlowTransmit.STOP:
                self._stop_flow(flow)

    def _stop_flow(self, flow):
        if flow['transmit'] == 'started':
            self._update_flow_runtime(flow['name'])
            flow['accumulated_frames_tx'] = flow['frames_tx']
            flow['accumulated_bytes_tx'] = flow['bytes_tx']
            flow['accumulated_frames_rx'] = flow['frames_rx']
            flow['accumulated_bytes_rx'] = flow['bytes_rx']
        flow['transmit'] = 'stopped'
        flow['start_time'] = None
        flow['stop_time'] = time.time()
        flow['frames_tx_rate'] = 0.0
        flow['frames_rx_rate'] = 0.0
        flow['bytes_tx_rate'] = 0.0
        flow['bytes_rx_rate'] = 0.0

    def _resolve_arp_all(self):
        '''Simulates ARP / Neighbor Discovery across all emulated devices.'''
        if not self._config:
            return
        for device in self._config.devices:
            state = self._devices.setdefault(
                device.name, {'name': device.name, 'arp_resolved': {}})
            for eth in device.ethernets:
                for addresses, unset in ((eth.ipv4_addresses, '0.0.0.0'),
                                         (eth.ipv6_addresses, '::')):
                    for address in addresses:
                        gateway = address.gateway
                        if gateway and gateway not in (unset, ''):
                            state['arp_resolved'][gateway] = '00:00:02:00:00:02'

    # -- test hooks -----------------------------------------------------------

    def allocate_dhcpv4_lease(self, mac_src, requested_ip=None):
        '''Simulates a DHCPv4 DORA lease allocation.'''
        if requested_ip and requested_ip != '0.0.0.0':
            assigned = requested_ip
        else:
            assigned = '192.0.2.{}'.format(self._dhcp_pool_next)
            self._dhcp_pool_next += 1
        return {'mac': mac_src, 'ip': assigned, 'netmask': '255.255.255.0',
                'gateway': '192.0.2.1', 'lease_time': 3600}

    def get_arp_table(self, device_name):
        return dict(self._devices.get(device_name, {}).get('arp_resolved', {}))

    def set_counter_reset_on_start(self, enabled=True):
        '''Models a backend that zeroes a flow's counters each time it starts.

        IxNetwork behaves this way; ixia-c keeps counters monotonic. With this
        enabled a burst is also metered over time rather than completing at
        once, so the reset is observable exactly as it is on hardware.
        '''
        self._reset_on_start = bool(enabled)

    def set_flow_loss(self, flow_name, loss_pct=None, loss_frames=None):
        '''Injects loss on a flow, as a percentage and/or a frame count.'''
        self._pending_loss[flow_name] = {'loss_pct': loss_pct,
                                         'loss_frames': loss_frames}
        flow = self._flows.get(flow_name)
        if flow is not None:
            if loss_pct is not None:
                flow['loss_pct'] = float(loss_pct)
            if loss_frames is not None:
                flow['loss_frames'] = int(loss_frames)
            self._simulate_flow(flow_name)

    def set_port_link(self, port_name, state):
        '''Sets a port link to ``up`` or ``down``.

        Link state is a property of the chassis, not the configuration, so it
        is remembered for ports that have not been configured yet.
        '''
        state = str(state).lower()
        self._pending_link[port_name] = state
        if port_name in self._ports:
            self._ports[port_name]['link'] = state
        for flow in self._flows.values():
            if port_name in (flow['tx_port'], flow['rx_port']):
                self._simulate_flow(flow['name'])

    def get_port_link(self, port_name):
        if port_name not in self._ports:
            return 'down'
        return self._ports[port_name].get('link', 'up')

    def warnings(self):
        return list(self._warnings)

    def reset_counters(self):
        '''Simulates a hardware counter reset / chassis reboot.'''
        for flow in self._flows.values():
            for key in ('frames_tx', 'frames_rx', 'bytes_tx', 'bytes_rx',
                        'accumulated_frames_tx', 'accumulated_bytes_tx',
                        'accumulated_frames_rx', 'accumulated_bytes_rx'):
                flow[key] = 0
        for port in self._ports.values():
            for key in ('frames_tx', 'frames_rx', 'bytes_tx', 'bytes_rx'):
                port[key] = 0

    # -- simulation -----------------------------------------------------------

    def _dropped_frames(self, flow, transmitted):
        dropped = int(round(transmitted * (flow['loss_pct'] / 100.0)))
        if flow['loss_pct'] > 0 and dropped == 0:
            dropped = 1
        return dropped + flow['loss_frames']

    def _simulate_flow(self, flow_name):
        flow = self._flows.get(flow_name)
        if not flow:
            return

        tx_up = self.get_port_link(flow['tx_port']) == 'up'
        rx_up = self.get_port_link(flow['rx_port']) == 'up'

        if flow['duration_type'] in ('fixed_packets', 'burst') and \
                not self._reset_on_start:
            total_tx = int(flow['target_packets'] or 1)
            if tx_up:
                flow['frames_tx'] += total_tx
                flow['bytes_tx'] += total_tx * flow['frame_size']

            if tx_up and rx_up:
                received = max(0, total_tx - self._dropped_frames(flow, total_tx))
                flow['frames_rx'] += received
                flow['bytes_rx'] += received * flow['frame_size']

            flow['accumulated_frames_tx'] = flow['frames_tx']
            flow['accumulated_bytes_tx'] = flow['bytes_tx']
            flow['accumulated_frames_rx'] = flow['frames_rx']
            flow['accumulated_bytes_rx'] = flow['bytes_rx']

            # Fixed-size bursts complete transmission immediately.
            flow['transmit'] = 'stopped'
            rate = flow['pps'] or 100.0
            flow['frames_tx_rate'] = float(rate) if tx_up else 0.0
            rx_rate = rate * (1.0 - (flow['loss_pct'] / 100.0))
            flow['frames_rx_rate'] = \
                max(0.0, float(rx_rate)) if (tx_up and rx_up) else 0.0
            flow['bytes_tx_rate'] = flow['frames_tx_rate'] * flow['frame_size']
            flow['bytes_rx_rate'] = flow['frames_rx_rate'] * flow['frame_size']

        elif flow['transmit'] == 'started':
            self._update_flow_runtime(flow_name)

        self._recompute_port_counters()

    def _update_flow_runtime(self, flow_name):
        flow = self._flows.get(flow_name)
        if not flow or flow['transmit'] != 'started':
            return

        tx_up = self.get_port_link(flow['tx_port']) == 'up'
        rx_up = self.get_port_link(flow['rx_port']) == 'up'

        rate = flow['pps'] or 100.0
        if self._reset_on_start:
            # Metered like hardware, so a restart is observable while the
            # counters are still climbing.
            elapsed = (time.time() - flow['start_time']) if flow['start_time'] else 0.0
            cycle_tx = int(round(rate * elapsed))
        else:
            elapsed = max(1.0, time.time() - flow['start_time']) \
                if flow['start_time'] else 1.0
            cycle_tx = max(1, int(round(rate * elapsed)))

        target = flow['target_packets']
        if target and flow['duration_type'] in ('fixed_packets', 'burst'):
            cycle_tx = min(cycle_tx, int(target))
            if cycle_tx >= int(target):
                flow['transmit'] = 'stopped'

        base_tx = flow['accumulated_frames_tx']
        base_tx_bytes = flow['accumulated_bytes_tx']
        base_rx = flow['accumulated_frames_rx']
        base_rx_bytes = flow['accumulated_bytes_rx']

        flow['frames_tx'] = base_tx + (cycle_tx if tx_up else 0)
        flow['bytes_tx'] = base_tx_bytes + \
            ((cycle_tx * flow['frame_size']) if tx_up else 0)
        flow['frames_tx_rate'] = float(rate) if tx_up else 0.0
        flow['bytes_tx_rate'] = \
            float(rate * flow['frame_size']) if tx_up else 0.0

        if tx_up and rx_up:
            cycle_rx = max(0, cycle_tx - self._dropped_frames(flow, cycle_tx))
            flow['frames_rx'] = base_rx + cycle_rx
            flow['bytes_rx'] = base_rx_bytes + (cycle_rx * flow['frame_size'])
            rx_rate = max(0.0, rate * (1.0 - (flow['loss_pct'] / 100.0)))
            flow['frames_rx_rate'] = float(rx_rate)
            flow['bytes_rx_rate'] = float(rx_rate * flow['frame_size'])
        else:
            flow['frames_rx'] = base_rx
            flow['bytes_rx'] = base_rx_bytes
            flow['frames_rx_rate'] = 0.0
            flow['bytes_rx_rate'] = 0.0

    def _recompute_port_counters(self):
        for port in self._ports.values():
            port.update({'frames_tx': 0, 'frames_rx': 0,
                         'bytes_tx': 0, 'bytes_rx': 0,
                         'frames_tx_rate': 0.0, 'frames_rx_rate': 0.0,
                         'bytes_tx_rate': 0.0, 'bytes_rx_rate': 0.0})

        for flow in self._flows.values():
            tx_port = self._ports.get(flow['tx_port'])
            if tx_port:
                tx_port['frames_tx'] += flow['frames_tx']
                tx_port['bytes_tx'] += flow['bytes_tx']
                tx_port['frames_tx_rate'] += flow['frames_tx_rate']
                tx_port['bytes_tx_rate'] += flow['bytes_tx_rate']

            rx_port = self._ports.get(flow['rx_port'])
            if rx_port:
                rx_port['frames_rx'] += flow['frames_rx']
                rx_port['bytes_rx'] += flow['bytes_rx']
                rx_port['frames_rx_rate'] += flow['frames_rx_rate']
                rx_port['bytes_rx_rate'] += flow['bytes_rx_rate']

    # -- telemetry ------------------------------------------------------------

    def get_metrics(self, request):
        choice = getattr(request, 'choice', None)

        if choice == MetricsRequest.FLOW:
            names = getattr(request.flow, 'flow_names', None) or list(self._flows)
            metrics = []
            for name in names:
                flow = self._flows.get(name)
                if flow is None:
                    continue
                if flow['transmit'] == 'started':
                    self._update_flow_runtime(name)
                loss_pct = (max(0, flow['frames_tx'] - flow['frames_rx']) /
                            flow['frames_tx'] * 100.0) if flow['frames_tx'] else 0.0
                metrics.append(FlowMetric(
                    name=name,
                    frames_tx=flow['frames_tx'], frames_rx=flow['frames_rx'],
                    bytes_tx=flow['bytes_tx'], bytes_rx=flow['bytes_rx'],
                    frames_tx_rate=flow['frames_tx_rate'],
                    frames_rx_rate=flow['frames_rx_rate'],
                    tx_rate_bytes=flow['bytes_tx_rate'],
                    rx_rate_bytes=flow['bytes_rx_rate'],
                    loss_percent=round(loss_pct, 4),
                    transmit=flow['transmit']))
            return MetricsResponse(flow_metrics=metrics)

        if choice == MetricsRequest.PORT:
            self._recompute_port_counters()
            names = getattr(request.port, 'port_names', None) or list(self._ports)
            metrics = []
            for name in names:
                port = self._ports.get(name)
                if port is None:
                    continue
                metrics.append(PortMetric(
                    name=name,
                    frames_tx=port['frames_tx'], frames_rx=port['frames_rx'],
                    bytes_tx=port['bytes_tx'], bytes_rx=port['bytes_rx'],
                    frames_tx_rate=port['frames_tx_rate'],
                    frames_rx_rate=port['frames_rx_rate'],
                    tx_rate_bytes=port['bytes_tx_rate'],
                    rx_rate_bytes=port['bytes_rx_rate'],
                    link=port['link']))
            return MetricsResponse(port_metrics=metrics)

        return MetricsResponse()


# -----------------------------------------------------------------------------
# API client
# -----------------------------------------------------------------------------

class MockOtgApi:
    '''OTG API client backed by :class:`MockOtgEngine` or a REST controller.

    Implements the subset of the snappi ``Api`` surface that
    ``genie.trafficgen.otg`` relies on, so the plugin behaves identically
    whether or not the snappi SDK is installed.
    '''

    def __init__(self, location=None, transport='mock', timeout=30):
        self.location = location
        self.transport = str(getattr(transport, 'value', transport) or
                             'mock').lower().rsplit('.', 1)[-1]
        self.timeout = timeout
        self._engine = MockOtgEngine()
        self._warnings = []

    @property
    def engine(self):
        '''Underlying simulation engine, for loss injection and assertions.'''
        return self._engine

    # -- model factories ------------------------------------------------------

    def config(self):
        return Config()

    def control_state(self):
        return ControlState()

    def metrics_request(self):
        return MetricsRequest()

    # -- operations -----------------------------------------------------------

    def set_config(self, config):
        if self._is_remote():
            response = self._request('POST', '/config',
                                     config.serialize().encode('utf-8'))
            self._warnings = response.get('warnings', []) \
                if isinstance(response, dict) else []
            return response
        response = self._engine.set_config(config)
        self._warnings = response.get('warnings', [])
        return response

    def get_config(self):
        if self._is_remote():
            config = Config()
            config.deserialize(self._request('GET', '/config', raw=True))
            return config
        return self._engine.get_config()

    def set_control_state(self, control_state):
        if self._is_remote():
            return self._request(
                'POST', '/control/state',
                json.dumps(control_state.to_dict()).encode('utf-8'))
        return self._engine.set_control_state(control_state)

    def get_metrics(self, request):
        if self._is_remote():
            response = self._request('POST', '/monitor/metrics',
                                     json.dumps(request.to_dict()).encode('utf-8'))
            return MetricsResponse(
                flow_metrics=[FlowMetric(**m)
                              for m in response.get('flow_metrics', [])],
                port_metrics=[PortMetric(**m)
                              for m in response.get('port_metrics', [])])
        return self._engine.get_metrics(request)

    def warnings(self):
        return list(self._warnings)

    # -- transport ------------------------------------------------------------

    def _is_remote(self):
        return bool(self.transport in ('http', 'https') and self.location and
                    str(self.location).startswith(('http://', 'https://')))

    def _request(self, method, path, data=None, raw=False):
        request = urllib.request.Request(
            '{}{}'.format(self.location, path), data=data, method=method,
            headers={'Content-Type': 'application/json'} if data else {})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode('utf-8')
        except (urllib.error.URLError, OSError) as err:
            raise GenieTgnError(
                "Request to OTG controller '{loc}{path}' failed: {err}".format(
                    loc=self.location, path=path, err=err)) from err
        if raw:
            return body
        return json.loads(body) if body else {'status': 'success'}
