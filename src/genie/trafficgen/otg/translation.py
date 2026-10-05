'''
Translation engine mapping the legacy imperative Genie TrafficGen calls onto
the declarative Open Traffic Generator (OTG) model.

Each legacy call is rendered as OTG ports, emulated devices and flows, then
pushed to the controller as a single declarative configuration. Statistics are
read back through typed OTG metrics and re-shaped into the dictionaries the
legacy pyATS APIs return.
'''

import time
import socket
import hashlib
import logging
import ipaddress

from prettytable import PrettyTable

from genie.harness.exceptions import GenieTgnError

log = logging.getLogger(__name__)

# Fallback addressing used when send_arp/send_ns must synthesize emulated
# devices because the script configured flows only.
DEFAULT_IPV4_HOST = '192.0.2.10'
DEFAULT_IPV4_GATEWAY = '192.0.2.1'
DEFAULT_IPV6_HOST = '2001:db8::2'
DEFAULT_IPV6_GATEWAY = '2001:db8::1'


class OtgTranslationEngine:
    '''Implements the legacy-to-OTG mapping for :class:`~.implementation.Otg`.

    Provides five-tier receiving port inference, emulated device synthesis for
    ARP/ND, partitioned flow and port counter baselines, counter-reset
    resilience, and clamped loss/outage arithmetic.
    '''

    def __init__(self, tgn):
        self.tgn = tgn

    # -------------------------------------------------------------------------
    # Plugin state proxies
    # -------------------------------------------------------------------------

    @property
    def device(self):
        return self.tgn.device

    @property
    def _api(self):
        return self.tgn._api

    @property
    def _config(self):
        return self.tgn._config

    @_config.setter
    def _config(self, value):
        self.tgn._config = value

    @property
    def _traffic_streams(self):
        return self.tgn._traffic_streams

    @property
    def _flow_baselines(self):
        return self.tgn._flow_baselines

    @property
    def _port_baselines(self):
        return self.tgn._port_baselines

    @property
    def _config_dirty(self):
        return self.tgn._config_dirty

    @_config_dirty.setter
    def _config_dirty(self, value):
        self.tgn._config_dirty = value

    @property
    def _controller_has_flows(self):
        return self.tgn._controller_has_flows

    @_controller_has_flows.setter
    def _controller_has_flows(self, value):
        self.tgn._controller_has_flows = value

    def _sync_controller_flow_state(self):
        '''Record whether the applied controller configuration has flows.'''
        self._controller_has_flows = bool(
            getattr(self._config, 'flows', None))

    def _check_connected(self):
        if not self.tgn.connected or self._api is None:
            raise GenieTgnError(
                "Not connected to OTG controller for device '{}'. Call "
                "connect() first.".format(getattr(self.device, 'name', 'unknown')))

    def commit(self):
        '''Pushes the in-memory configuration when it has pending edits.'''
        if self._config_dirty:
            self._api.set_config(self._config)
            self._config_dirty = False
            self._sync_controller_flow_state()

    # -------------------------------------------------------------------------
    # Core helpers
    # -------------------------------------------------------------------------

    def _get_port_mac(self, port_name):
        '''Resolves a port MAC from the testbed, else a deterministic digest.'''
        device = self.device
        if device is not None and getattr(device, 'interfaces', None):
            interface = device.interfaces.get(port_name)
            if interface is not None and getattr(interface, 'mac', None):
                return str(interface.mac)
        # blake2s, not hash(): str hashing is salted per process by PYTHONHASHSEED.
        digest = hashlib.blake2s(str(port_name).encode('utf-8'),
                                 digest_size=2).digest()
        return '00:00:01:00:{:02x}:{:02x}'.format(digest[0], digest[1])

    def port_location(self, port_name):
        '''Derives an OTG port location from the testbed interface or link.'''
        device = self.device
        if device is not None and getattr(device, 'interfaces', None):
            interface = device.interfaces.get(port_name)
            if interface is not None:
                location = getattr(interface, 'location', None)
                if location:
                    return str(location)
                link = getattr(interface, 'link', None)
                if link is not None:
                    return str(getattr(link, 'name', link))
        return str(port_name)

    def _resolve_port(self, interface):
        '''Resolves an interface identifier to a port name, registering it.'''
        if interface is None:
            return None

        if hasattr(interface, 'name'):
            port_name = str(interface.name)
        elif isinstance(interface, int):
            if self._config and 1 <= interface <= len(self._config.ports):
                port_name = self._config.ports[interface - 1].name
            else:
                port_name = 'port_{}'.format(interface)
        else:
            port_name = str(interface).strip()

        if self._config is not None:
            if port_name not in [p.name for p in self._config.ports]:
                self._config.ports.add(name=port_name,
                                       location=self.port_location(port_name))
                self._config_dirty = True

        return port_name

    def _infer_rx_port(self, tx_port_name, dst_ip=None, **kwargs):
        '''Infers the receiving port through a five-tier resolution hierarchy.

        Binding a receiving port is what makes Rx telemetry - and
        therefore loss measurement - possible, so this never returns None.
        '''
        # Tier 1: explicit keyword arguments.
        explicit = (kwargs.get('rx_interface') or kwargs.get('dst_interface') or
                    kwargs.get('rx_port') or kwargs.get('dst_port') or
                    kwargs.get('receiving_interface') or kwargs.get('rx_name'))
        if explicit is not None:
            return self._resolve_port(explicit)

        device = self.device
        interfaces = getattr(device, 'interfaces', None) or {}

        # Tier 2: destination IP subnet match against testbed interfaces.
        if dst_ip and interfaces:
            try:
                destination = ipaddress.ip_address(str(dst_ip))
            except ValueError:
                destination = None
            if destination is not None:
                for name, interface in interfaces.items():
                    if name == tx_port_name:
                        continue
                    address = (getattr(interface, 'ipv4', None)
                               if destination.version == 4
                               else getattr(interface, 'ipv6', None))
                    if not address:
                        continue
                    try:
                        network = ipaddress.ip_interface(str(address)).network
                    except ValueError:
                        continue
                    if destination in network:
                        return self._resolve_port(name)

        # Tier 3: topology link peer on the same traffic generator.
        if tx_port_name in interfaces:
            link = getattr(interfaces[tx_port_name], 'link', None)
            if link is not None and getattr(link, 'interfaces', None):
                for peer in link.interfaces:
                    if peer is interfaces[tx_port_name]:
                        continue
                    if getattr(peer, 'device', None) is device:
                        return self._resolve_port(peer.name)

        # Tier 4: next configured port.
        if self._config:
            candidates = [p.name for p in self._config.ports
                          if p.name != tx_port_name]
            if candidates:
                return candidates[0]

        # Tier 5: single-port loopback.
        return tx_port_name

    def _link_peer_address(self, port_name, is_ipv6=False):
        '''Returns the address of the peer across this port's testbed link.'''
        device = self.device
        interfaces = getattr(device, 'interfaces', None) or {}
        interface = interfaces.get(port_name)
        link = getattr(interface, 'link', None) if interface is not None else None
        if link is None:
            return None

        for peer in getattr(link, 'interfaces', []):
            if peer is interface or getattr(peer, 'device', None) is device:
                continue
            address = getattr(peer, 'ipv6' if is_ipv6 else 'ipv4', None)
            if address:
                return str(ipaddress.ip_interface(str(address)).ip)
        return None

    def _resolve_gateway(self, port_name, src_ip, dst_ip, prefix, **kwargs):
        '''Resolves the next hop an emulated device should resolve through.

        The legacy APIs never took a gateway, so it is derived from the
        testbed: the peer across the port's link is the router carrying the
        traffic. Only a directly connected destination doubles as the next hop.
        '''
        explicit = kwargs.get('gateway') or kwargs.get('gw_ip')
        if explicit:
            return str(explicit)

        is_ipv6 = ':' in str(src_ip)
        peer = self._link_peer_address(port_name, is_ipv6=is_ipv6)
        if peer:
            return peer

        try:
            network = ipaddress.ip_interface(
                '{ip}/{prefix}'.format(ip=src_ip, prefix=prefix)).network
            if ipaddress.ip_address(str(dst_ip)) in network:
                return str(dst_ip)
        except ValueError:
            pass

        log.warning(
            "Could not determine a gateway for '%s' on port '%s'; pass a "
            'gateway= keyword or give the link peer an address in the testbed '
            'so ARP and Neighbor Discovery can resolve', src_ip, port_name)
        return None

    def _ensure_device(self, port_name, ip_address, gateway=None, prefix=None,
                       mac=None):
        '''Ensures an emulated device owns ``ip_address`` on ``port_name``.

        Returns the emulated IP endpoint, whose name is what a flow binds to
        when it uses device endpoints.
        '''
        if not self._config:
            return None

        is_ipv6 = ':' in str(ip_address)
        unset_gateway = '::' if is_ipv6 else '0.0.0.0'

        for device in self._config.devices:
            for eth in device.ethernets:
                if eth.connection.port_name != port_name:
                    continue
                addresses = eth.ipv6_addresses if is_ipv6 else eth.ipv4_addresses
                for address in addresses:
                    if address.address != str(ip_address):
                        continue
                    if gateway and address.gateway in (None, '', unset_gateway):
                        address.gateway = str(gateway)
                        self._config_dirty = True
                    return address

        name = 'dev_{port}_{ip}'.format(
            port=self._sanitize(port_name),
            ip=str(ip_address).replace('.', '_').replace(':', '_'))
        device = self._config.devices.add(name=name)

        eth = device.ethernets.add(name='eth_{}'.format(name),
                                   mac=mac or self._get_port_mac(port_name))
        eth.connection.port_name = port_name

        if is_ipv6:
            endpoint = eth.ipv6_addresses.add(
                name='ipv6_{}'.format(name),
                address=str(ip_address),
                gateway=str(gateway) if gateway else '::',
                prefix=int(prefix or 64))
        else:
            endpoint = eth.ipv4_addresses.add(
                name='ipv4_{}'.format(name),
                address=str(ip_address),
                gateway=str(gateway) if gateway else '0.0.0.0',
                prefix=int(prefix or 24))

        self._config_dirty = True
        return endpoint

    @staticmethod
    def _sanitize(name):
        '''Makes a port name safe to embed in generated OTG object names.'''
        return str(name).replace('/', '_').replace(' ', '_')

    @staticmethod
    def _bind_ports(flow, tx_name, rx_name):
        '''Binds a flow between two ports.

        Prefers rx_names; OTG deprecated the singular rx_name in favour of it.
        '''
        port = flow.tx_rx.port
        port.tx_name = tx_name
        if rx_name is None:
            return
        if hasattr(port, 'rx_names'):
            port.rx_names = [rx_name]
        else:
            port.rx_name = rx_name

    def _endpoint_port(self, names):
        '''Maps emulated IP endpoint names back to the port hosting them.'''
        wanted = set(names or [])
        for device in (self._config.devices if self._config else []):
            for eth in device.ethernets:
                for address in (list(eth.ipv4_addresses) +
                                list(eth.ipv6_addresses)):
                    if address.name in wanted:
                        return eth.connection.port_name
        return None

    def flow_endpoints(self, flow):
        '''Returns the (tx, rx) port names a flow transmits between.'''
        tx_rx = flow.tx_rx
        if getattr(tx_rx, 'choice', 'port') == 'device':
            return (self._endpoint_port(tx_rx.device.tx_names),
                    self._endpoint_port(tx_rx.device.rx_names))
        port = tx_rx.port
        rx_names = getattr(port, 'rx_names', None)
        return port.tx_name, rx_names[0] if rx_names else port.rx_name

    def get_flow_expected_pps(self, flow_name):
        '''Returns the configured transmit rate of a flow, or 0.0.'''
        for flow in (self._config.flows if self._config else []):
            if flow.name != flow_name:
                continue
            pps = getattr(getattr(flow, 'rate', None), 'pps', None)
            if pps is not None and float(pps) > 0:
                return float(pps)
        return 0.0

    @staticmethod
    def _resolve_flow_name(stream):
        return getattr(stream, 'name', str(stream))

    @staticmethod
    def _as_flow_names(streams):
        '''Normalizes a stream argument into a list of flow names, or None.'''
        if not streams:
            return None
        if isinstance(streams, str) or not isinstance(streams, (list, tuple, set)):
            streams = [streams]
        return [OtgTranslationEngine._resolve_flow_name(s) for s in streams]

    @staticmethod
    def _normalize_rate_tolerance(value):
        '''Returns a rate tolerance as a percentage.

        Values below 1.0 are read as fractions (0.01 -> 1%), 1.0 and above as
        percentages (5 -> 5%), matching legacy genietrafficgen call sites.
        '''
        tolerance = float(value)
        return tolerance * 100.0 if tolerance < 1.0 else tolerance

    def _build_dhcp_request_payload(self, mac_src, requested_ip, xid=0):
        '''Builds an RFC 2131 BOOTP/DHCP Request payload.'''
        transaction_id = int(xid) if xid else 0x3903F326
        flags = 0x8000  # broadcast
        unset_address = b'\x00\x00\x00\x00'

        clean_mac = mac_src.replace(':', '').replace('-', '').replace('.', '')
        try:
            mac_bytes = bytes.fromhex(clean_mac)
        except ValueError as err:
            raise GenieTgnError(
                "Invalid source MAC address '{}'".format(mac_src)) from err
        if len(mac_bytes) != 6:
            raise GenieTgnError(
                "Invalid source MAC address '{}'".format(mac_src))

        try:
            requested_ip_bytes = socket.inet_aton(str(requested_ip))
        except OSError as err:
            raise GenieTgnError(
                "Invalid requested IPv4 address '{}'".format(requested_ip)) from err

        payload = (
            bytes([1, 1, 6, 0]) +                       # op, htype, hlen, hops
            transaction_id.to_bytes(4, 'big') +         # xid
            (0).to_bytes(2, 'big') +                    # secs
            flags.to_bytes(2, 'big') +
            unset_address * 4 +                         # ciaddr yiaddr siaddr giaddr
            mac_bytes + b'\x00' * 10 +                  # chaddr
            b'\x00' * 64 +                              # sname
            b'\x00' * 128 +                             # file
            bytes([99, 130, 83, 99]) +                  # magic cookie
            bytes([53, 1, 3]) +                         # option 53: DHCPREQUEST
            bytes([50, 4]) + requested_ip_bytes +       # option 50: requested IP
            bytes([255])                                # option 255: end
        )
        return payload.ljust(300, b'\x00')

    def _apply_transmit_mode(self, flow, transmit_mode, pkts_per_burst, gap=12):
        '''Maps a legacy transmit_mode string onto an OTG flow duration.'''
        if transmit_mode == 'single_burst':
            flow.duration.fixed_packets.packets = int(pkts_per_burst)
            flow.duration.choice = 'fixed_packets'
        elif transmit_mode == 'continuous':
            flow.duration.continuous.gap = int(gap)
            flow.duration.choice = 'continuous'
        elif transmit_mode == 'multi_burst':
            flow.duration.burst.packets = int(pkts_per_burst)
            flow.duration.choice = 'burst'
        else:
            raise GenieTgnError(
                "Unsupported transmit_mode '{mode}'. Expected one of: "
                'single_burst, continuous, multi_burst'.format(mode=transmit_mode))

    # -------------------------------------------------------------------------
    # Traffic stream configuration
    # -------------------------------------------------------------------------

    def _configure_data_traffic(self, ip_version, interface, src_ip, dst_ip,
                                l4_protocol, payload=None,
                                transmit_mode='single_burst',
                                pkts_per_burst=1, pps=100, **kwargs):
        '''Shared IPv4/IPv6 imperative-to-declarative stream translation.'''
        self._check_connected()
        port_name = self._resolve_port(interface)
        rx_port_name = self._infer_rx_port(port_name, dst_ip=dst_ip, **kwargs)

        prefix = kwargs.get('prefix', 24 if ip_version == 4 else 64)
        tx_endpoint = self._ensure_device(
            port_name=port_name,
            ip_address=src_ip,
            gateway=self._resolve_gateway(port_name, src_ip, dst_ip, prefix,
                                          **kwargs),
            prefix=prefix,
            mac=kwargs.get('src_mac'))

        # Emulating the destination as well lets the flow use device endpoints,
        # so the generator resolves both MACs by ARP/ND. Without it a routed
        # flow leaves with an unresolved destination MAC and the DUT drops it.
        rx_endpoint = None
        if kwargs.get('emulate_destination', True) and rx_port_name != port_name:
            rx_endpoint = self._ensure_device(
                port_name=rx_port_name,
                ip_address=dst_ip,
                gateway=self._resolve_gateway(rx_port_name, dst_ip, src_ip,
                                              prefix,
                                              gateway=kwargs.get('dst_gateway')),
                prefix=prefix,
                mac=kwargs.get('dst_port_mac'))

        flow_name = (kwargs.get('flow_name') or kwargs.get('name') or
                     'flow_ipv{v}_{port}_{idx}'.format(
                         v=ip_version, port=self._sanitize(port_name),
                         idx=len(self._config.flows) + 1))

        flow = self._config.flows.add(name=flow_name)
        if tx_endpoint is not None and rx_endpoint is not None:
            flow.tx_rx.device.tx_names = [tx_endpoint.name]
            flow.tx_rx.device.rx_names = [rx_endpoint.name]
        else:
            self._bind_ports(flow, port_name, rx_port_name)

        ethernet = flow.packet.ethernet()[-1]
        ethernet.src.value = kwargs.get('src_mac') or self._get_port_mac(port_name)
        # Left on the OTG 'auto' default otherwise, so the destination MAC is
        # resolved from the emulated device's gateway rather than hard coded.
        if kwargs.get('dst_mac'):
            ethernet.dst.value = kwargs['dst_mac']

        header = (flow.packet.ipv4() if ip_version == 4
                  else flow.packet.ipv6())[-1]
        header.src.value = str(src_ip)
        header.dst.value = str(dst_ip)

        protocol = str(l4_protocol).lower()
        if protocol in ('tcp', 'udp'):
            l4 = getattr(flow.packet, protocol)()[-1]
            l4.src_port.value = int(kwargs.get('src_port', 5000))
            l4.dst_port.value = int(kwargs.get('dst_port', 5001))
        elif protocol not in ('', 'none', 'ip'):
            raise GenieTgnError(
                "Unsupported l4_protocol '{}'. Expected 'tcp' or 'udp'.".format(
                    l4_protocol))

        if payload:
            custom = flow.packet.custom()[-1]
            custom.bytes = (payload.encode('utf-8') if isinstance(payload, str)
                            else bytes(payload)).hex()

        flow.rate.pps = int(pps)
        self._apply_transmit_mode(flow, transmit_mode, pkts_per_burst,
                                  kwargs.get('gap', 12))

        flow.metrics.enable = True
        flow.metrics.loss = True

        self._traffic_streams.append(flow_name)
        self._config_dirty = True
        log.info("Configured OTG IPv%s flow '%s' from port '%s' to port '%s'",
                 ip_version, flow_name, port_name, rx_port_name)
        return flow_name

    def configure_ipv4_data_traffic(self, interface, src_ip, dst_ip,
                                    l4_protocol, payload=None,
                                    transmit_mode='single_burst',
                                    pkts_per_burst=1, pps=100, **kwargs):
        '''Translates an imperative IPv4 stream request into an OTG flow.'''
        return self._configure_data_traffic(
            4, interface, src_ip, dst_ip, l4_protocol, payload,
            transmit_mode, pkts_per_burst, pps, **kwargs)

    def configure_ipv6_data_traffic(self, interface, src_ip, dst_ip,
                                    l4_protocol, payload=None,
                                    transmit_mode='single_burst',
                                    pkts_per_burst=1, pps=100, **kwargs):
        '''Translates an imperative IPv6 stream request into an OTG flow.'''
        return self._configure_data_traffic(
            6, interface, src_ip, dst_ip, l4_protocol, payload,
            transmit_mode, pkts_per_burst, pps, **kwargs)

    def configure_dhcpv4_request(self, interface, mac_src, requested_ip,
                                 xid=0, transmit_mode='single_burst',
                                 pkts_per_burst=1, pps=100, **kwargs):
        '''Builds an RFC 2131 DHCPv4 Request stream.'''
        self._check_connected()
        port_name = self._resolve_port(interface)
        rx_port_name = self._infer_rx_port(port_name, **kwargs)

        flow_name = kwargs.get('flow_name') or 'flow_dhcpv4_req_{port}_{idx}'.format(
            port=port_name, idx=len(self._config.flows) + 1)

        flow = self._config.flows.add(name=flow_name)
        self._bind_ports(flow, port_name, rx_port_name)

        ethernet = flow.packet.ethernet()[-1]
        ethernet.src.value = mac_src
        ethernet.dst.value = 'ff:ff:ff:ff:ff:ff'

        ipv4 = flow.packet.ipv4()[-1]
        ipv4.src.value = '0.0.0.0'
        ipv4.dst.value = '255.255.255.255'

        udp = flow.packet.udp()[-1]
        udp.src_port.value = 68
        udp.dst_port.value = 67

        custom = flow.packet.custom()[-1]
        custom.bytes = self._build_dhcp_request_payload(
            mac_src, requested_ip, xid).hex()

        flow.rate.pps = int(pps)
        self._apply_transmit_mode(flow, transmit_mode, pkts_per_burst,
                                  kwargs.get('gap', 12))
        flow.metrics.enable = True

        self._traffic_streams.append(flow_name)
        self._config_dirty = True
        return flow_name

    def send_arp_request(self, interface, mac_src, ip_src, ip_target,
                         vlan_tag=0, count=1, pps=100, **kwargs):
        '''Transmits raw ARP Request frames without protocol emulation.'''
        self._check_connected()
        port_name = self._resolve_port(interface)
        flow_name = 'flow_arp_req_{port}_{idx}'.format(
            port=port_name, idx=len(self._config.flows) + 1)

        flow = self._config.flows.add(name=flow_name)
        self._bind_ports(flow, port_name,
                         self._infer_rx_port(port_name, **kwargs))

        ethernet = flow.packet.ethernet()[-1]
        ethernet.src.value = mac_src
        ethernet.dst.value = 'ff:ff:ff:ff:ff:ff'
        ethernet.ether_type.value = 0x0806

        arp = flow.packet.arp()[-1]
        arp.hardware_type.value = 1
        arp.protocol_type.value = 0x0800
        arp.hardware_length.value = 6
        arp.protocol_length.value = 4
        arp.operation.value = 1
        arp.src_hardware_addr.value = mac_src
        arp.src_protocol_addr.value = ip_src
        arp.dst_hardware_addr.value = '00:00:00:00:00:00'
        arp.dst_protocol_addr.value = ip_target

        flow.rate.pps = int(pps)
        flow.duration.fixed_packets.packets = int(count)
        flow.duration.choice = 'fixed_packets'
        flow.metrics.enable = False

        self._api.set_config(self._config)
        self._config_dirty = False
        self._sync_controller_flow_state()

        state = self._api.control_state()
        state.choice = state.TRAFFIC
        state.traffic.choice = state.traffic.FLOW_TRANSMIT
        state.traffic.flow_transmit.state = state.traffic.flow_transmit.START
        state.traffic.flow_transmit.flow_names = [flow_name]
        self._api.set_control_state(state)

        return flow_name

    # -------------------------------------------------------------------------
    # Protocol emulation
    # -------------------------------------------------------------------------

    def _start_protocols(self, wait_time, host, gateway, prefix):
        '''Starts protocol emulation, synthesizing devices when none exist.'''
        self._check_connected()
        if self._config is not None and not len(self._config.devices):
            for port in self._config.ports:
                self._ensure_device(port_name=port.name, ip_address=host,
                                    gateway=gateway, prefix=prefix)

        if self._config_dirty:
            self.commit()
            self._flow_baselines.clear()
            self._port_baselines.clear()

        state = self._api.control_state()
        state.choice = state.PROTOCOL
        state.protocol.choice = state.protocol.ALL
        state.protocol.all.state = state.protocol.all.START
        self._api.set_control_state(state)

        if wait_time and float(wait_time) > 0:
            time.sleep(float(wait_time))
        return True

    def send_arp(self, wait_time=0, **kwargs):
        '''Triggers ARP resolution across all emulated devices.'''
        return self._start_protocols(wait_time, DEFAULT_IPV4_HOST,
                                     DEFAULT_IPV4_GATEWAY, 24)

    def send_ns(self, wait_time=10, **kwargs):
        '''Triggers IPv6 Neighbor Solicitation across all emulated devices.'''
        return self._start_protocols(wait_time, DEFAULT_IPV6_HOST,
                                     DEFAULT_IPV6_GATEWAY, 64)

    def stop_all_protocols(self, wait_time=30, **kwargs):
        '''Stops protocol emulation on all emulated devices.'''
        self._check_connected()
        state = self._api.control_state()
        state.choice = state.PROTOCOL
        state.protocol.choice = state.protocol.ALL
        state.protocol.all.state = state.protocol.all.STOP
        self._api.set_control_state(state)

        if wait_time and float(wait_time) > 0:
            time.sleep(float(wait_time))
        return True

    # -------------------------------------------------------------------------
    # Traffic control
    # -------------------------------------------------------------------------

    def start_traffic(self, wait_time=0, port=None, traffic_streams=None,
                      **kwargs):
        '''Commits pending configuration and starts flow transmission.'''
        self._check_connected()
        self.commit()

        state = self._api.control_state()
        state.choice = state.TRAFFIC
        state.traffic.choice = state.traffic.FLOW_TRANSMIT
        state.traffic.flow_transmit.state = state.traffic.flow_transmit.START

        flow_names = self._as_flow_names(
            traffic_streams or kwargs.get('traffic_stream') or
            kwargs.get('streams') or kwargs.get('stream'))
        if flow_names:
            state.traffic.flow_transmit.flow_names = flow_names

        self._api.set_control_state(state)
        self._clamp_baselines(flow_names)

        if wait_time and float(wait_time) > 0:
            time.sleep(float(wait_time))
        return True

    def _clamp_baselines(self, flow_names=None):
        '''Lowers baselines for counters that restarted when traffic started.

        Some backends reset a flow's counters each time it starts. That is only
        observable right after the start: by the time statistics are checked
        the counters may have climbed back past the stale baseline, making the
        run look as though it transmitted nothing.
        '''
        if not (self._flow_baselines or self._port_baselines):
            return

        for metric in self._baseline_metrics('flow'):
            if flow_names is not None and metric.name not in flow_names:
                continue
            self._clamp(self._flow_baselines.get(metric.name), metric)

        for metric in self._baseline_metrics('port'):
            self._clamp(self._port_baselines.get(metric.name), metric)

    @classmethod
    def _clamp(cls, baseline, metric):
        '''A baseline can never exceed the counter it offsets.'''
        if baseline is None:
            return
        for field, value in cls._snapshot(metric).items():
            if value < baseline[field]:
                baseline[field] = value

    def stop_traffic(self, wait_time=0, port=None, max_time=180,
                     traffic_streams=None, **kwargs):
        '''Stops transmission and waits for flows to report ``stopped``.'''
        self._check_connected()
        flow_names = self._as_flow_names(
            traffic_streams or kwargs.get('traffic_stream') or
            kwargs.get('streams') or kwargs.get('stream'))

        state = self._api.control_state()
        state.choice = state.TRAFFIC
        state.traffic.choice = state.traffic.FLOW_TRANSMIT
        state.traffic.flow_transmit.state = state.traffic.flow_transmit.STOP
        if flow_names:
            state.traffic.flow_transmit.flow_names = flow_names
        self._api.set_control_state(state)

        deadline = time.time() + float(max_time)
        while True:
            request = self._api.metrics_request()
            request.choice = request.FLOW
            if flow_names:
                request.flow.flow_names = flow_names
            response = self._api.get_metrics(request)
            pending = self._still_transmitting(response.flow_metrics, flow_names)
            if not pending:
                break
            if time.time() >= deadline:
                raise GenieTgnError(
                    "Flows did not reach 'stopped' state within {t}s: "
                    '{f}'.format(t=max_time, f=', '.join(sorted(pending))))
            time.sleep(0.05)

        if wait_time and float(wait_time) > 0:
            time.sleep(float(wait_time))
        return True

    @staticmethod
    def _still_transmitting(metrics, flow_names=None):
        '''Returns the flows that have yet to stop.

        A flow that has transmitted nothing is not waited on. Some backends
        report transmit state from the counters rather than from the flow
        itself, and call anything with no frames 'started', which would leave
        a flow that never sent holding up the stop for ever.
        '''
        return [m.name for m in (metrics or [])
                if (flow_names is None or m.name in flow_names)
                and getattr(m, 'transmit', 'stopped') != 'stopped'
                and (getattr(m, 'frames_tx', 0) or 0) > 0]

    def clear_traffic(self):
        '''Stops and removes every configured traffic stream.'''
        self._check_connected()
        try:
            if self._config is not None and len(self._config.flows):
                state = self._api.control_state()
                state.choice = state.TRAFFIC
                state.traffic.choice = state.traffic.FLOW_TRANSMIT
                state.traffic.flow_transmit.state = \
                    state.traffic.flow_transmit.STOP
                self._api.set_control_state(state)
        except Exception as err:
            log.warning('Failed to stop flows before clearing traffic: %s', err)

        if self._config is not None:
            self._config.flows.clear()
            self._api.set_config(self._config)
            self._config_dirty = False
            self._sync_controller_flow_state()

        self._traffic_streams.clear()
        self._flow_baselines.clear()
        return True

    # -------------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------------

    def clear_statistics(self, wait_time=0, clear_port_stats=True,
                         clear_protocol_stats=True, **kwargs):
        '''Snapshots current counters as baselines for relative statistics.

        OTG counters are monotonic, so "clearing" records an offset rather than
        zeroing hardware registers.
        '''
        self._check_connected()
        self.commit()

        for metric in self._baseline_metrics('flow'):
            self._flow_baselines[metric.name] = self._snapshot(metric)

        if clear_port_stats:
            for metric in self._baseline_metrics('port'):
                self._port_baselines[metric.name] = self._snapshot(metric)

        if wait_time and float(wait_time) > 0:
            time.sleep(float(wait_time))
        return True

    def _baseline_metrics(self, kind):
        '''Reads metrics for baselining, tolerating a controller with none yet.

        Some backends only materialize their statistics views once traffic has
        run, so a failure here means there are no counters to offset against.
        '''
        request = self._api.metrics_request()
        request.choice = getattr(request, kind.upper())
        try:
            response = self._api.get_metrics(request)
        except Exception as err:
            log.warning('No %s statistics to baseline yet, treating counters '
                        'as zero: %s', kind, err)
            return []
        return getattr(response, '{}_metrics'.format(kind)) or []

    @staticmethod
    def _counter(metric, field):
        '''Reads an optional OTG metric field.

        The OTG schema marks most counters optional and backends omit the ones
        they cannot map, so a missing field means zero rather than an error.
        '''
        return float(getattr(metric, field, 0) or 0)

    @staticmethod
    def _snapshot(metric):
        return {
            'frames_tx': int(getattr(metric, 'frames_tx', 0) or 0),
            'frames_rx': int(getattr(metric, 'frames_rx', 0) or 0),
            'bytes_tx': int(getattr(metric, 'bytes_tx', 0) or 0),
            'bytes_rx': int(getattr(metric, 'bytes_rx', 0) or 0),
        }

    @staticmethod
    def _relative(metric, baselines, field):
        '''Returns a counter relative to its baseline, re-zeroing on reset.

        A counter below its baseline means the chassis reset its registers, so
        the stale baseline is discarded rather than producing negative deltas.
        '''
        current = int(getattr(metric, field, 0) or 0)
        baseline = baselines.get(metric.name)
        if baseline is None:
            return current
        if current < baseline[field]:
            baseline[field] = 0
        return max(0, current - baseline[field])

    def check_traffic_loss(self, traffic_streams=None, max_outage=120,
                           loss_tolerance=15, rate_tolerance=5,
                           check_iteration=10, check_interval=60,
                           outage_dict=None, clear_stats=False,
                           clear_stats_time=30, pre_check_wait=None,
                           raise_on_loss=True, **kwargs):
        '''Validates loss, outage and rate for each stream against tolerances.

        Returns one ``{"stream": {name: {...}}}`` entry per iteration, matching
        the structure the Genie harness consumes from the Ixia plugins.
        '''
        self._check_connected()
        self.commit()

        iterations = int(check_iteration)
        if iterations < 1:
            raise GenieTgnError(
                "'check_iteration' must be greater than zero, got "
                '{}'.format(check_iteration))

        if clear_stats:
            self.clear_statistics(wait_time=clear_stats_time)

        if pre_check_wait:
            log.info("Waiting '%s' seconds before checking traffic streams for "
                     'loss/outage', pre_check_wait)
            time.sleep(float(pre_check_wait))

        streams = (traffic_streams or kwargs.get('traffic_stream') or
                   kwargs.get('streams') or kwargs.get('stream') or
                   self._traffic_streams)
        flow_names = self._as_flow_names(streams)
        if not flow_names:
            raise GenieTgnError(
                'No traffic data found: no traffic streams are configured')

        duplicates = {n for n in flow_names if flow_names.count(n) > 1}
        if duplicates:
            raise GenieTgnError(
                'Duplicate traffic streams found: {}'.format(sorted(duplicates)))

        log.info('Configured traffic streams: %s', flow_names)

        traffic_data_set = []
        failures = []

        for iteration in range(iterations):
            request = self._api.metrics_request()
            request.choice = request.FLOW
            request.flow.flow_names = flow_names
            response = self._api.get_metrics(request)

            metrics = list(response.flow_metrics or [])
            missing = sorted(set(flow_names) - {m.name for m in metrics})
            if missing:
                # Without counters there is nothing to judge, so passing here
                # would be a false negative rather than a clean run.
                raise GenieTgnError(
                    'No traffic data found for traffic streams: '
                    '{}'.format(', '.join(missing)))

            stream_data = {}
            failures = []
            for metric in metrics:
                stream_data[metric.name], stream_failures = self._evaluate_flow(
                    metric, max_outage, loss_tolerance, rate_tolerance,
                    outage_dict)
                failures.extend(stream_failures)

            traffic_data_set.append({'stream': stream_data})

            log.info('Traffic statistics, check %s/%s:\n%s',
                     iteration + 1, iterations,
                     self._stream_table(stream_data))

            # A breach is only an error when it will actually fail the check:
            # with raise_on_loss=False the caller is measuring rather than
            # enforcing, and before the last iteration traffic may still
            # converge.
            last_iteration = iteration == iterations - 1
            enforced = bool(failures) and raise_on_loss and last_iteration
            for failure in failures:
                log.log(logging.ERROR if enforced else logging.INFO,
                        '* %s', failure)

            if not failures:
                break
            if iteration < iterations - 1:
                time.sleep(float(check_interval))

        if failures and raise_on_loss:
            raise GenieTgnError(
                'Unexpected traffic outage/loss observed on streams: '
                '{}'.format(', '.join(sorted(set(failures)))))

        return traffic_data_set

    @staticmethod
    def _stream_table(stream_data):
        '''Renders per-stream statistics for the log, as the Ixia plugins do.'''
        columns = ['Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %',
                   'Tx Frame Rate', 'Rx Frame Rate', 'Outage (seconds)', 'State']
        table = PrettyTable()
        table.field_names = ['Traffic Item'] + columns
        for name, row in sorted(stream_data.items()):
            table.add_row([name] + [row[column] for column in columns])
        return table

    def _evaluate_flow(self, metric, max_outage, loss_tolerance,
                       rate_tolerance, outage_dict):
        '''Scores one flow metric, returning its row and any tolerance breaches.'''
        frames_tx = self._relative(metric, self._flow_baselines, 'frames_tx')
        frames_rx = self._relative(metric, self._flow_baselines, 'frames_rx')
        delta = max(0, frames_tx - frames_rx)
        loss_pct = (delta / frames_tx) * 100.0 if frames_tx else 0.0

        configured_pps = self.get_flow_expected_pps(metric.name)
        tx_rate = self._counter(metric, 'frames_tx_rate')
        rx_rate = self._counter(metric, 'frames_rx_rate')
        expected_pps = configured_pps if configured_pps > 0 else tx_rate

        outage = delta / expected_pps if (expected_pps > 0 and delta > 0) else 0.0

        loss_tol, rate_tol, outage_tol = self._stream_tolerances(
            metric.name, outage_dict, loss_tolerance, rate_tolerance, max_outage)

        row = {
            'Tx Frames': frames_tx,
            'Rx Frames': frames_rx,
            'Frames Delta': delta,
            'Loss %': round(loss_pct, 4),
            'Tx Frame Rate': tx_rate,
            'Rx Frame Rate': rx_rate,
            'Tx Rate (Bps)': self._counter(metric, 'tx_rate_bytes'),
            'Rx Rate (Bps)': self._counter(metric, 'rx_rate_bytes'),
            'Outage (seconds)': round(outage, 4),
            'State': getattr(metric, 'transmit', 'unknown'),
        }

        failures = []

        # Only a flow that is meant to be sending can be faulted for sending
        # nothing: a fixed_packets flow that finished before the counters were
        # baselined legitimately reads tx=0, and so does any stopped flow.
        if frames_tx == 0 and expected_pps > 0 and row['State'] != 'stopped':
            failures.append(
                '{name}: no traffic transmitted (tx=0, expected_rate={rate} '
                'pps)'.format(name=metric.name, rate=expected_pps))
            return row, failures

        if loss_pct > float(loss_tol):
            failures.append('{name}: loss={loss:.2f}% > tol={tol}%'.format(
                name=metric.name, loss=loss_pct, tol=loss_tol))

        failures.extend(self._check_rate(metric, expected_pps, tx_rate, rx_rate,
                                         rate_tol))

        if outage_tol is not None and outage > float(outage_tol):
            failures.append(
                '{name}: outage={outage:.4f}s > max_outage={tol}s'.format(
                    name=metric.name, outage=outage, tol=outage_tol))

        return row, failures

    @staticmethod
    def _stream_tolerances(flow_name, outage_dict, loss_tolerance,
                           rate_tolerance, max_outage):
        '''Applies any per-stream tolerance overrides from ``outage_dict``.'''
        if not isinstance(outage_dict, dict):
            return loss_tolerance, rate_tolerance, max_outage

        entry = None
        streams = outage_dict.get('traffic_streams')
        if isinstance(streams, dict):
            entry = streams.get(flow_name)
        elif flow_name in outage_dict:
            entry = outage_dict[flow_name]

        if isinstance(entry, dict):
            return (entry.get('loss_tolerance', loss_tolerance),
                    entry.get('rate_tolerance', rate_tolerance),
                    entry.get('max_outage', max_outage))
        if isinstance(entry, (int, float)):
            return entry, rate_tolerance, max_outage
        return loss_tolerance, rate_tolerance, max_outage

    def _check_rate(self, metric, expected_pps, tx_rate, rx_rate, rate_tolerance):
        '''Compares the received rate against the configured transmit rate.'''
        if rate_tolerance is None:
            return []

        # A stopped flow is not sending, so neither rate can be held against
        # the configured one - a finished burst would read as total deviation.
        # The transmit state decides that, not the rate counters, which can
        # still carry a residual sample from the window the flow stopped in.
        if getattr(metric, 'transmit', None) == 'stopped':
            return []

        if expected_pps > 0:
            tolerance_pct = self._normalize_rate_tolerance(rate_tolerance)
            deviation = abs(rx_rate - expected_pps) / expected_pps * 100.0
            if deviation > tolerance_pct:
                return ['{name}: rate deviation {dev:.2f}% (rx={rx:.1f} pps, '
                        'target={target:.1f} pps) > tol={tol:.2f}%'.format(
                            name=metric.name, dev=deviation, rx=rx_rate,
                            target=expected_pps, tol=tolerance_pct)]
            return []

        difference = abs(tx_rate - rx_rate)
        if difference > float(rate_tolerance):
            return ['{name}: rate diff {diff:.1f} pps > tol={tol} pps'.format(
                name=metric.name, diff=difference, tol=rate_tolerance)]
        return []

    def get_stats(self, view='Port Statistics', **kwargs):
        '''Returns port or flow statistics as a legacy-style dictionary.'''
        self._check_connected()
        view_name = str(view).lower()

        if 'port' in view_name:
            request = self._api.metrics_request()
            request.choice = request.PORT
            return {
                metric.name: {
                    'Frames Tx': self._relative(metric, self._port_baselines,
                                                'frames_tx'),
                    'Frames Rx': self._relative(metric, self._port_baselines,
                                                'frames_rx'),
                    'Bytes Tx': self._relative(metric, self._port_baselines,
                                               'bytes_tx'),
                    'Bytes Rx': self._relative(metric, self._port_baselines,
                                               'bytes_rx'),
                    'Link': getattr(metric, 'link', 'up'),
                }
                for metric in self._api.get_metrics(request).port_metrics
            }

        if 'flow' in view_name or 'traffic' in view_name:
            request = self._api.metrics_request()
            request.choice = request.FLOW
            stats = {}
            for metric in self._api.get_metrics(request).flow_metrics:
                frames_tx = self._relative(metric, self._flow_baselines,
                                           'frames_tx')
                frames_rx = self._relative(metric, self._flow_baselines,
                                           'frames_rx')
                delta = max(0, frames_tx - frames_rx)
                stats[metric.name] = {
                    'Tx Frames': frames_tx,
                    'Rx Frames': frames_rx,
                    'Frames Delta': delta,
                    'Loss %': round((delta / frames_tx) * 100.0, 4)
                    if frames_tx else 0.0,
                    'Tx Frame Rate': self._counter(metric, 'frames_tx_rate'),
                    'Rx Frame Rate': self._counter(metric, 'frames_rx_rate'),
                    'Tx Rate (Bps)': self._counter(metric, 'tx_rate_bytes'),
                    'Rx Rate (Bps)': self._counter(metric, 'rx_rate_bytes'),
                }
            return stats

        raise GenieTgnError("Unsupported statistics view: '{}'".format(view))
