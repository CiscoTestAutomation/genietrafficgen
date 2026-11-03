'''
Connection implementation class for Open Traffic Generator (OTG) devices.

Implements the Genie ``TrafficGen`` interface on top of the Open Traffic
Generator model (https://github.com/open-traffic-generator) and offers two
modes of operation:

Legacy compatibility mode
    Existing imperative pyATS calls (``configure_ipv4_data_traffic``,
    ``send_arp``, ``start_traffic``, ``check_traffic_loss``, ...) are
    translated into declarative OTG ports, devices and flows.

Native declarative mode
    ``tgn.api``, ``tgn.config``, ``tgn.new_config()`` and ``tgn.set_config()``
    expose the OTG schema directly for scripts written against snappi.
'''

import importlib
import json
import os
import re
import struct
import time
import logging
import math
from shutil import copyfile
from urllib.parse import quote, urlparse

import yaml
from prettytable import PrettyTable

# pyATS
from pyats.log.utils import banner
from pyats.connections import BaseConnection
from pyats.easypy import runtime

# Genie
from genie.trafficgen.trafficgen import TRAFFICGEN_ENTRYPOINT, TrafficGen
from genie.harness.exceptions import GenieTgnError

from genie.trafficgen.ixnetwork import (
    configure_ixnetwork_licensing,
    normalize_ixia_license_servers,
)

from genie.trafficgen.otg.mock import MockOtgApi
from genie.trafficgen.otg.translation import OtgTranslationEngine

log = logging.getLogger(__name__)

RATE_ATTRIBUTES = ('pps', 'percentage', 'bps', 'kbps', 'mbps', 'gbps')

IXNETWORK_LICENSE_KEYS = (
    'ixia_license_server_ip',
    'ixnetwork_license_mode',
    'ixnetwork_license_tier',
)

# snappi_ixnetwork names the counter it failed to read in this warning.
ABSENT_COUNTER = re.compile(r"Could not set result value for column '(\w+)'")

# The backend logs per module, and rebuilds the parent's handlers whenever an
# api is created, so the filter has to sit on the children that emit.
BACKEND_LOGGERS = ('snappi_ixnetwork.trafficitem', 'snappi_ixnetwork.vport')


class AbsentCounterFilter(logging.Filter):
    '''Reports a counter the controller cannot supply once, not on every read.

    IxNetwork has no 'Tx Bytes' column, so its statistics rows have nothing to
    offer for bytes_tx and the backend warns about it for every flow on every
    metrics read. The first one says something; the rest are noise.
    '''

    def __init__(self):
        super().__init__()
        self._reported = set()

    def filter(self, record):
        match = ABSENT_COUNTER.search(record.getMessage())
        if match is None:
            return True

        counter = match.group(1)
        if counter in self._reported:
            return False

        self._reported.add(counter)
        record.msg = ("The traffic generator does not report '%s'; it will "
                      'read as zero for every flow' % counter)
        record.args = ()
        return True


# Statistics view and column names, as Ixia names them. Rows are looked up
# by these, so a misspelt one reads as a missing counter rather than failing.
FLOW_STATISTICS = 'Flow Statistics'
PORT_STATISTICS = 'Port Statistics'
TRAFFIC_ITEM_STATISTICS = 'Traffic Item Statistics'
TRAFFIC_ITEM = 'Traffic Item'
TX_FRAMES = 'Tx Frames'
RX_FRAMES = 'Rx Frames'
FRAMES_DELTA = 'Frames Delta'
TX_FRAME_RATE = 'Tx Frame Rate'
RX_FRAME_RATE = 'Rx Frame Rate'
LOSS_PERCENT = 'Loss %'

# Kept identical to the ixianative traffic profile so that profiles captured by
# either plugin remain comparable and pickle/unpickle interchangeably.
PROFILE_HEADERS = ['Source/Dest Port Pair', TRAFFIC_ITEM, TX_FRAMES,
                   RX_FRAMES, FRAMES_DELTA, TX_FRAME_RATE,
                   RX_FRAME_RATE, LOSS_PERCENT, 'Outage (seconds)']


def _artifact_path(directory, template, **components):
    '''Keep generated filenames inside their selected artifact directory.'''
    name = template.format(**{
        key: quote(str(value), safe='') for key, value in components.items()
    })
    destination = os.path.join(directory, name)
    root = os.path.realpath(directory)
    if os.path.commonpath((root, os.path.realpath(destination))) != root:
        raise OSError(
            'Generated artifact path escapes its destination directory: '
            '{}'.format(destination))
    return destination


def import_snappi():
    '''Imports the snappi SDK on demand.

    Deferred so that importing ``genie.trafficgen`` never pulls snappi or its
    gRPC dependencies into processes that only use ``transport: mock``.
    '''
    try:
        import snappi
    except ImportError as err:
        raise GenieTgnError(
            "The 'snappi' package is required for OTG transports 'http', "
            "'https' and 'grpc'. Reinstall it with "
            "'pip install genie.trafficgen', or use transport='mock' "
            'for hardware-free simulation.') from err
    return snappi


# snappi extensions that genie.trafficgen packages behind an install extra.
EXTENSION_EXTRAS = {'ixnetwork': 'genie.trafficgen[ixnetwork]'}


def import_snappi_extension(ext):
    '''Imports the snappi extension named by a connection's ``ext`` key.

    Extensions pin their dependencies tightly, so they are installed on
    request rather than by default. snappi reports a missing one only once the
    session is created, and without naming the package to install.
    '''
    name = str(ext).strip().replace('-', '_').lower()
    module = 'snappi_{}'.format(name)
    try:
        return importlib.import_module(module)
    except ImportError as err:
        install = EXTENSION_EXTRAS.get(name, 'snappi[{}]'.format(name))
        raise GenieTgnError(
            "The '{m}' package is required for an OTG connection with "
            "'ext: {e}'. Install it with 'pip install {i}'.".format(
                m=module, e=ext, i=install)) from err


class Otg(TrafficGen):
    '''OTG plugin, driving a controller that speaks the model natively.

    A package registered under the ``genie.trafficgen`` entry point can add a
    backend of its own by subclassing this and declaring the ``platform`` it
    answers to. See 'Extending the OTG plugin' in the plugin documentation.
    '''

    # The 'platform' values this class answers to, plus the device that names
    # no platform at all. A subclass declares its own, and does not inherit
    # these: a lookup that landed on the subclass asked for its platform.
    SUPPORTED_PLATFORMS = ('ixia',)
    DEFAULT_PLATFORM = 'ixia'

    SUPPORTED_TRANSPORTS = ('mock', 'http', 'https', 'grpc')
    DEFAULT_TRANSPORT = 'mock'

    # Whether the testbed interfaces are OTG test ports. A backend that
    # emulates sessions from host addresses has none.
    USES_TEST_PORTS = True

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.device = self.device or kwargs.get('device')
        self.via = kwargs.get('via', 'tgn')

        connection_info = self.connection_info

        # Genie's Device.platform falls back to the device type when no
        # platform is configured; its backing value keeps the two apart, so a
        # device of 'type: tgn' is not read as 'platform: tgn'.
        platform = getattr(self.device, '_platform',
                           getattr(self.device, 'platform', None))
        self.platform = str(platform or self.DEFAULT_PLATFORM).lower()
        if self.platform not in self.SUPPORTED_PLATFORMS:
            raise GenieTgnError(
                "Unsupported OTG platform '{p}' for device '{d}'. This plugin "
                'serves: {s}. A platform served by another package needs that '
                "package installed and registered under the '{e}' entry "
                'point.'.format(p=self.platform,
                                d=getattr(self.device, 'name', 'unknown'),
                                s=', '.join(self.SUPPORTED_PLATFORMS),
                                e=TRAFFICGEN_ENTRYPOINT))

        self.transport = str(connection_info.get(
            'transport', self.DEFAULT_TRANSPORT)).lower()
        self.location = connection_info.get('location')

        if self.transport not in self.SUPPORTED_TRANSPORTS:
            raise GenieTgnError(
                "Unsupported transport '{t}' for device '{d}'. Expected one "
                'of: {s}'.format(t=self.transport,
                                 d=getattr(self.device, 'name', 'unknown'),
                                 s=', '.join(self.SUPPORTED_TRANSPORTS)))

        # 'location: mock' is shorthand for the in-memory simulator.
        if self.location == 'mock':
            if 'mock' not in self.SUPPORTED_TRANSPORTS:
                raise GenieTgnError(
                    "Device '{d}': 'location: mock' selects the OTG "
                    "simulator, which platform '{p}' does not "
                    'provide'.format(
                        d=getattr(self.device, 'name', 'unknown'),
                        p=self.platform))
            self.transport = 'mock'

        # snappi extension driving a vendor backend, e.g. 'ixnetwork' or 'trex'.
        self.ext = connection_info.get('ext')

        self._validate_connection_options()

        if not self.location:
            self.location = self._default_location()

        # Verify TLS certificates by default. Labs that terminate on a
        # self-signed controller certificate must opt out explicitly with
        # 'verify_certificate: False' rather than shipping an insecure default.
        self.verify_certificate = connection_info.get(
            'verify_certificate', True)
        self.timeout = connection_info.get('timeout', 30)

        self._is_connected = False
        self._api = None
        self._config = None
        self._traffic_streams = []
        self._flow_baselines = {}
        self._port_baselines = {}
        self._config_dirty = False
        # Whether the controller currently holds an applied traffic
        # configuration. Tracked independently of local edits so cleanup can
        # stop remote traffic even after the local config has been replaced.
        self._controller_has_flows = False
        self._reference_packet_rate = {}
        self._first_sample_packet_rate = {}
        self._golden_profile = PrettyTable()
        # The last table create_flow_statistics_table() built, which
        # get_flow_statistics_table() returns.
        self._flow_statistics_table = None

        self.translation_engine = OtgTranslationEngine(self)

    # -------------------------------------------------------------------------
    # Backend hooks
    #
    # A subclass overrides these to drive a backend of its own. Each one
    # carries the behaviour of a controller that speaks OTG natively, so a
    # subclass overrides only what its backend does differently.
    # -------------------------------------------------------------------------

    def _validate_connection_options(self):
        '''Rejects connection keys this backend cannot honour.'''
        return None

    def _default_location(self):
        '''The controller location to use when the testbed names none.'''
        connection_info = self.connection_info
        if self.transport == 'grpc':
            return '{ip}:{port}'.format(
                ip=connection_info.get('ip', '127.0.0.1'),
                port=connection_info.get('port', 40051))
        return '{protocol}://{ip}:{port}'.format(
            protocol=connection_info.get('protocol', 'https'),
            ip=connection_info.get('ip', '127.0.0.1'),
            port=connection_info.get('port', 8443))

    def _create_api(self):
        '''Creates the OTG API client this backend drives.'''
        api = self._create_snappi_api()
        self._quieten_absent_counters()
        return api

    def _close_api(self):
        '''Releases whatever the API client holds open.

        Called while disconnecting, after traffic has been stopped. A snappi
        client holds no session of its own, so there is nothing to close.
        '''
        return None

    def _deserialize_config(self, payload):
        '''Builds a configuration object from a dict or a JSON/YAML payload.'''
        api = self._require_api()
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode()
        if isinstance(payload, str):
            try:
                payload = yaml.safe_load(payload)
            except yaml.YAMLError as err:
                raise GenieTgnError('The OTG configuration is not valid JSON '
                                    'or YAML: {}'.format(err)) from err
        # A file path is valid YAML too, and would push an empty configuration
        if not isinstance(payload, dict):
            raise GenieTgnError(
                'An OTG configuration is a mapping (ports, devices, flows, '
                '...), got {t} {v!r}; load_configuration() reads one from a '
                'file'.format(t=type(payload).__name__, v=payload))
        config = api.config()
        config.deserialize(json.dumps(payload))
        return config

    def _configuration_text(self, config):
        '''The text save_configuration() writes for a configuration, in a
        form load_configuration() reads back.'''
        payload = config.serialize() if hasattr(config, 'serialize') \
            else json.dumps(config, indent=2)
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode()
        return payload

    def _resolve_configuration_source(self, configuration):
        '''Resolves a configuration reference this backend understands.

        Returns ``(source, content)`` for a reference the backend resolved
        itself, or None to read ``configuration`` as a local file path.
        '''
        return None

    def _traffic_operation_is_noop(self, operation):
        '''Whether a traffic operation has nothing to do on this backend.'''
        return False

    def _check_update_supported(self):
        '''Checks what update_configuration() needs of this backend.

        Overridden by a backend that owns no OTG flows, or that cannot
        support the operation at all.
        '''
        self._require_configured_flows('update configuration')

    def _default_route_names(self):
        '''The route ranges set_route_state() acts on when given none.'''
        return [name for name, obj
                in self._walk_named_objects(self._config, set())
                if 'RouteRange' in type(obj).__name__]

    def _bgp_peer_names(self):
        '''OTG names of every BGP peer in the configuration, by family.'''
        names = {'bgpv4': [], 'bgpv6': []}
        for name, obj in self._walk_named_objects(self._config, set()):
            kind = type(obj).__name__
            if kind == 'BgpV4Peer':
                names['bgpv4'].append(name)
            elif kind == 'BgpV6Peer':
                names['bgpv6'].append(name)
        return names

    # -------------------------------------------------------------------------
    # Connection lifecycle
    # -------------------------------------------------------------------------

    @property
    def connected(self):
        '''Is the OTG controller session established'''
        return self._is_connected

    @BaseConnection.locked
    def connect(self, **kwargs):
        '''Connect to the OTG controller and initialize a session'''
        if self._is_connected:
            log.info('Already connected to OTG controller at %s', self.location)
            return True

        log.info(banner('Connecting to OTG controller'))
        log.info("Location: '%s', transport: '%s'%s", self.location,
                 self.transport,
                 ", ext: '{}'".format(self.ext) if self.ext else '')

        if any(key in self.connection_info for key in IXNETWORK_LICENSE_KEYS):
            self._configure_ixnetwork_licensing()

        if self.transport == 'mock':
            self._api = MockOtgApi(location=self.location, transport='mock',
                                   timeout=self.timeout)
        else:
            self._api = self._create_api()

        self._config = self._api.config()
        self._traffic_streams = []
        self._flow_baselines = {}
        self._port_baselines = {}
        self._config_dirty = False
        self._controller_has_flows = False

        if self.USES_TEST_PORTS:
            self._populate_ports_from_testbed()

        self._is_connected = True
        log.info("Connected to OTG controller for device '%s'",
                 getattr(self.device, 'name', 'unknown'))
        return True

    @staticmethod
    def _quieten_absent_counters():
        '''Collapses the backend's repeated warnings about missing counters.'''
        for name in BACKEND_LOGGERS:
            backend_log = logging.getLogger(name)
            if not any(isinstance(existing, AbsentCounterFilter)
                       for existing in backend_log.filters):
                backend_log.addFilter(AbsentCounterFilter())

    def _configure_ixnetwork_licensing(self):
        '''Apply requested IxNetwork license settings before Snappi connects.

        Snappi owns native OTG traffic configuration.  IxNetwork licensing is
        a controller-global setting, so the only supported bridge is a brief
        Tcl session before the extension creates or attaches ports.
        '''
        connection_info = self.connection_info
        if not any(key in connection_info for key in IXNETWORK_LICENSE_KEYS):
            return

        if str(self.ext or '').lower() != 'ixnetwork':
            raise GenieTgnError(
                'IxNetwork licensing keys require ext: ixnetwork on an OTG '
                'connection.')
        if self.transport == 'mock':
            raise GenieTgnError(
                'IxNetwork licensing keys cannot be used with transport: mock.')

        tcl_port = connection_info.get('ixnetwork_tcl_port')
        version = connection_info.get('ixnetwork_version')
        missing = [
            key for key, value in (
                ('ixnetwork_tcl_port', tcl_port),
                ('ixnetwork_version', version),
            ) if value in (None, '')
        ]
        if missing:
            raise GenieTgnError(
                'IxNetwork licensing requires {}.'.format(', '.join(missing)))

        license_servers = None
        if 'ixia_license_server_ip' in connection_info:
            license_servers = normalize_ixia_license_servers(
                connection_info.get('ixia_license_server_ip'))
            if not license_servers:
                raise GenieTgnError(
                    'ixia_license_server_ip must contain at least one server.')

        controller_host = connection_info.get('ip')
        if not controller_host:
            parsed = urlparse(
                self.location if '://' in self.location
                else '//' + self.location)
            controller_host = parsed.hostname
        if not controller_host:
            raise GenieTgnError(
                'IxNetwork licensing requires an IP address or URL hostname.')

        credentials = getattr(self.device, 'credentials', None)
        configure_ixnetwork_licensing(
            controller_host=str(controller_host), tcl_port=tcl_port,
            version=version, license_servers=license_servers,
            license_mode=self._ixnetwork_license_scalar('ixnetwork_license_mode'),
            license_tier=self._ixnetwork_license_scalar('ixnetwork_license_tier'),
            credentials=credentials)

    def _ixnetwork_license_scalar(self, key):
        """Validate an optional scalar licensing connection setting."""
        if key not in self.connection_info:
            return None
        value = self.connection_info.get(key)
        if not isinstance(value, str) or not value.strip():
            raise GenieTgnError(
                '{} must be a non-empty string.'.format(key))
        return value.strip()

    def _create_snappi_api(self):
        '''Builds a real snappi client for the http/https/grpc transports.'''
        snappi = import_snappi()
        kwargs = {'location': self.location, 'verify': self.verify_certificate}

        # snappi rejects ext and transport together: an extension owns its own
        # transport to the vendor backend.
        if self.ext:
            import_snappi_extension(self.ext)
            kwargs['ext'] = self.ext
        else:
            kwargs['transport'] = (snappi.Transport.GRPC
                                   if self.transport == 'grpc'
                                   else snappi.Transport.HTTP)

        try:
            return snappi.api(**kwargs)
        except Exception as err:
            raise GenieTgnError(
                "Failed to initialise OTG session at '{loc}' (transport={t}"
                "{ext}): {err}".format(
                    loc=self.location, t=self.transport,
                    ext=", ext={}".format(self.ext) if self.ext else '',
                    err=err)) from err

    def _populate_ports_from_testbed(self):
        '''Registers each testbed interface as an OTG port.'''
        interfaces = getattr(self.device, 'interfaces', None)
        if not interfaces:
            return
        for name in interfaces:
            self._config.ports.add(
                name=str(name),
                location=self.translation_engine.port_location(str(name)))
        self._config_dirty = True

    @BaseConnection.locked
    def disconnect(self):
        '''Stop traffic and terminate the OTG controller session'''
        if not self._is_connected:
            return True

        log.info(banner('Disconnecting from OTG controller'))
        try:
            # Stop traffic whenever the controller holds an applied
            # configuration, regardless of pending local edits. Replacing the
            # local config (e.g. via new_config()) does not stop flows the
            # controller is already transmitting.
            if self._controller_has_flows:
                self.stop_traffic(max_time=30)
        except Exception as err:
            log.warning('Failed to stop traffic while disconnecting: %s', err)
        finally:
            if self._api is not None:
                try:
                    self._close_api()
                except Exception as err:
                    log.warning('Failed to close the OTG session: %s', err)
            self._is_connected = False
            self._api = None
            self._config = None
            self._traffic_streams = []
            self._flow_baselines = {}
            self._port_baselines = {}
            self._config_dirty = False
            self._controller_has_flows = False
        return True

    # -------------------------------------------------------------------------
    # Native declarative mode
    # -------------------------------------------------------------------------

    @property
    def api(self):
        '''The underlying OTG API client (snappi client, or the simulator)'''
        return self._api

    @property
    def config(self):
        '''The in-memory OTG configuration'''
        return self._config

    @property
    def engine(self):
        '''The simulation engine, when running with ``transport: mock``'''
        return getattr(self._api, 'engine', None)

    def _require_api(self):
        if self._api is None:
            raise GenieTgnError(
                "Not connected to OTG controller for device '{}'. Call "
                'connect() first.'.format(
                    getattr(self.device, 'name', 'unknown')))
        return self._api

    def _require_configured_flows(self, operation):
        self._require_api()
        if self._config is None or len(self._config.flows) == 0:
            raise GenieTgnError(
                "Cannot {}: no OTG flows are configured".format(operation))

    def new_config(self):
        '''Create and adopt an empty OTG configuration'''
        self._config = self._require_api().config()
        self._traffic_streams.clear()
        self._flow_baselines.clear()
        self._port_baselines.clear()
        self._config_dirty = True
        return self._config

    def set_config(self, config):
        '''Push a declarative OTG configuration to the controller

        Accepts an OTG config object, a dict, or a JSON/YAML string.
        '''
        api = self._require_api()

        if isinstance(config, (dict, str, bytes, bytearray)):
            config = self._deserialize_config(config)

        api.set_config(config)
        self._config = config
        self._traffic_streams = [f.name for f in getattr(config, 'flows', [])]
        self._config_dirty = False
        self._controller_has_flows = bool(getattr(config, 'flows', None))
        self._flow_baselines.clear()
        self._port_baselines.clear()
        return True

    def get_config(self):
        '''Retrieve the configuration currently applied on the controller'''
        if self._api is None:
            return self._config
        return self._api.get_config()

    @staticmethod
    def _request_object(factory, request):
        '''An OTG request object, built from a dict or a JSON/YAML string
        when the caller (a trigger datafile, say) holds it that way.'''
        if not isinstance(request, (dict, str, bytes, bytearray)):
            return request
        if isinstance(request, dict):
            request = json.dumps(request)
        built = factory()
        built.deserialize(request)
        return built

    def set_state(self, state):
        '''Push an OTG control state (traffic, protocol or port)

        Accepts a control state object, a dict, or a JSON/YAML string.
        '''
        api = self._require_api()
        return api.set_control_state(
            self._request_object(api.control_state, state))

    def get_metrics(self, request):
        '''Retrieve typed OTG metrics for a metrics request

        Accepts a metrics request object, a dict, or a JSON/YAML string.
        '''
        api = self._require_api()
        return api.get_metrics(
            self._request_object(api.metrics_request, request))

    def get_states(self, request):
        '''Retrieve OTG protocol or link operational states

        Accepts a states request object, a dict, or a JSON/YAML string.
        '''
        api = self._require_api()
        if not hasattr(api, 'get_states'):
            raise GenieTgnError(
                'get_states() requires the snappi SDK and an OTG controller '
                "that supports it; it is not available with transport='mock'.")
        return api.get_states(
            self._request_object(api.states_request, request))

    # -------------------------------------------------------------------------
    # Legacy compatibility mode
    # -------------------------------------------------------------------------

    def configure_ipv4_data_traffic(self, *args, **kwargs):
        '''Configure an IPv4 data traffic stream'''
        return self.translation_engine.configure_ipv4_data_traffic(*args, **kwargs)

    def configure_ipv6_data_traffic(self, *args, **kwargs):
        '''Configure an IPv6 data traffic stream'''
        return self.translation_engine.configure_ipv6_data_traffic(*args, **kwargs)

    def configure_dhcpv4_request(self, *args, **kwargs):
        '''Configure a DHCPv4 Request stream'''
        return self.translation_engine.configure_dhcpv4_request(*args, **kwargs)

    def send_arp(self, *args, **kwargs):
        '''Resolve ARP for all emulated devices'''
        return self.translation_engine.send_arp(*args, **kwargs)

    def send_arp_request(self, *args, **kwargs):
        '''Transmit raw ARP Request frames'''
        return self.translation_engine.send_arp_request(*args, **kwargs)

    def send_ns(self, *args, **kwargs):
        '''Resolve IPv6 neighbors for all emulated devices'''
        return self.translation_engine.send_ns(*args, **kwargs)

    def start_traffic(self, *args, **kwargs):
        '''Start transmitting configured traffic streams'''
        if self._traffic_operation_is_noop('start traffic'):
            return True
        self._require_configured_flows('start traffic')
        return self.translation_engine.start_traffic(*args, **kwargs)

    def stop_traffic(self, *args, **kwargs):
        '''Stop transmitting configured traffic streams'''
        return self.translation_engine.stop_traffic(*args, **kwargs)

    def clear_traffic(self):
        '''Remove all configured traffic streams'''
        return self.translation_engine.clear_traffic()

    def clear_statistics(self, *args, **kwargs):
        '''Baseline all counters so subsequent statistics are relative'''
        return self.translation_engine.clear_statistics(*args, **kwargs)

    def check_traffic_loss(self, *args, **kwargs):
        '''Check each traffic stream for loss, outage and rate deviation'''
        if self._traffic_operation_is_noop('check traffic loss'):
            return []
        self._require_configured_flows('check traffic loss')
        return self.translation_engine.check_traffic_loss(*args, **kwargs)

    def get_stats(self, *args, **kwargs):
        '''Return port or flow statistics as a dictionary'''
        # Allow get_stats to return empty result after clear_traffic
        return self.translation_engine.get_stats(*args, **kwargs)

    # -------------------------------------------------------------------------
    # Genie harness compatibility
    # -------------------------------------------------------------------------

    def _archive_configuration(self, source, content):
        '''Write a loaded configuration into the run directory to be archived

        Outside easypy there is no archive and ``runtime.directory`` is just the
        current working directory, so nothing is written.
        '''
        if not getattr(runtime, 'runinfo', None):
            log.debug('Not running under easypy; OTG configuration from '
                      "'%s' will not be archived", source)
            return None

        try:
            destination = _artifact_path(
                runtime.directory, '{d}_{f}', d=self.device.name,
                f=os.path.basename(source))
            with open(destination, 'w') as archived:
                archived.write(content)
        except OSError as err:
            # Archiving is a side effect of loading, so it must never be the
            # reason a run fails.
            log.warning("Unable to archive OTG configuration from '%s': %s",
                        source, err)
            return None

        log.info("Archived OTG configuration as '%s'", destination)
        return destination

    @BaseConnection.locked
    def load_configuration(self, configuration, wait_time=60):
        '''Load an OTG configuration file (JSON or YAML) onto the controller'''
        log.info(banner("Loading OTG configuration '{}'".format(configuration)))
        resolved = self._resolve_configuration_source(configuration)
        if resolved is not None:
            content = resolved[1]
        else:
            try:
                with open(configuration) as config_file:
                    content = config_file.read()
            except OSError as err:
                raise GenieTgnError(
                    "Unable to read OTG configuration file "
                    "'{c}': {e}".format(c=configuration, e=err)) from err

        # Before the push: a configuration the controller rejects is the one
        # most worth having in the archive.
        self._archive_configuration(configuration, content)

        self.set_config(content)
        log.info("Loaded OTG configuration with %s port(s), %s device(s) and "
                 '%s flow(s)', len(self._config.ports),
                 len(self._config.devices), len(self._config.flows))
        self._wait(wait_time, 'after loading configuration')
        return True

    @BaseConnection.locked
    def remove_configuration(self, wait_time=30):
        '''Remove the configuration currently applied on the controller'''
        log.info(banner('Removing OTG configuration'))
        api = self._require_api()
        self._config = api.config()
        api.set_config(self._config)
        self._traffic_streams.clear()
        self._flow_baselines.clear()
        self._port_baselines.clear()
        self._config_dirty = False
        self._controller_has_flows = False
        self._wait(wait_time, 'after removing configuration')
        return True

    @BaseConnection.locked
    def assign_ixia_ports(self, wait_time=15):
        '''No-op retained for Genie harness compatibility

        OTG binds ports to their test locations declaratively as part of the
        configuration, so there is no separate port assignment step.
        '''
        self._require_api()
        log.info('OTG ports are bound declaratively by the configuration; '
                 'no port assignment step is required')
        return True

    @BaseConnection.locked
    def apply_traffic(self, wait_time=60):
        '''Apply the pending OTG configuration to the controller'''
        log.info(banner('Applying OTG configuration'))
        self._require_api()
        self.translation_engine.commit()
        self._wait(wait_time, 'after applying configuration')
        return True

    @BaseConnection.locked
    def start_all_protocols(self, wait_time=60):
        '''Start protocol emulation on all emulated devices'''
        log.info(banner('Starting all OTG protocols'))
        attempts = 3
        for attempt in range(1, attempts + 1):
            try:
                return self.translation_engine.send_arp(wait_time=wait_time)
            except Exception as err:
                message = str(err).lower()
                transient = ('operation' in message and 'progress' in message)
                transient = transient or 'clearing statistics' in message
                if not transient or attempt == attempts:
                    raise
                delay = min(5 * attempt, 10)
                log.warning(
                    "IxNetwork is still busy starting protocols; retrying "
                    "in %ss (%s/%s): %s", delay, attempt, attempts, err)
                time.sleep(delay)

    @BaseConnection.locked
    def stop_all_protocols(self, wait_time=60):
        '''Stop protocol emulation on all emulated devices'''
        log.info(banner('Stopping all OTG protocols'))
        return self.translation_engine.stop_all_protocols(wait_time=wait_time)

    def get_traffic_stream_names(self):
        '''Return the names of all configured traffic streams'''
        self._require_api()
        return [flow.name for flow in self._config.flows]

    @BaseConnection.locked
    def generate_traffic_streams(self, traffic_streams=None, wait_time=15):
        '''Commit the given traffic streams to the controller'''
        self._require_api()
        configured = self.get_traffic_stream_names()

        requested = traffic_streams or configured
        if isinstance(requested, str):
            requested = [requested]

        unknown = [name for name in requested if name not in configured]
        if unknown:
            raise GenieTgnError(
                'Traffic streams not found in OTG configuration: '
                '{}'.format(', '.join(sorted(unknown))))

        self.translation_engine.commit()
        self._wait(wait_time, 'after generating traffic streams')
        return True

    def _stop_applied_configuration(self, stop_max_time):
        '''Stop controller state before replacing an applied configuration.'''
        if not self._controller_has_flows:
            return

        # Go through the translation engine here rather than start_traffic's
        # public counterpart: a caller may have replaced the local model with
        # new_config() while the controller is still transmitting the old one.
        self.translation_engine.stop_traffic(max_time=stop_max_time)
        self.translation_engine.stop_all_protocols(wait_time=0)

    def _start_applied_configuration(self, wait_time):
        '''Bring a pushed OTG configuration to a measurable running state.'''
        self.apply_traffic(wait_time=0)
        # start_all_protocols() performs IPv4 ARP resolution.  Neighbor
        # discovery is a separate OTG operation, so perform it explicitly as
        # well; it is harmless for IPv4-only configurations and required for
        # native dual-stack configurations.
        self.start_all_protocols(wait_time=wait_time)
        self.send_ns(wait_time=0)
        self.start_traffic(wait_time=wait_time)
        self.clear_statistics(wait_time=0)

    @staticmethod
    def _walk_children(node):
        '''Return the already-materialised children of an OTG model object.'''
        items = getattr(node, '_items', None)
        if isinstance(items, list):
            return items
        if isinstance(node, (list, tuple, set)):
            return node
        if isinstance(node, dict):
            return node.values()

        properties = getattr(node, '_properties', None)
        if isinstance(properties, dict):
            return properties.values()
        if hasattr(node, '__dict__'):
            return vars(node).values()
        return ()

    @staticmethod
    def _walk_object_name(node):
        '''Read an OTG object's name without selecting an unset choice.'''
        properties = getattr(node, '_properties', None)
        if isinstance(properties, dict):
            return properties.get('name')
        if hasattr(node, '__dict__'):
            return vars(node).get('name')
        return None

    @staticmethod
    def _walk_named_objects(node, seen):
        '''Yields every (name, object) pair reachable in a configuration.

        Only properties that are already set are followed: reading a snappi
        choice property is enough to select it, which would rewrite the
        configuration being inspected.
        '''
        if node is None or isinstance(node, (str, bytes, int, float, bool)):
            return
        if id(node) in seen:
            return
        seen.add(id(node))

        name = Otg._walk_object_name(node)
        if isinstance(name, str) and name:
            yield name, node

        for value in Otg._walk_children(node):
            yield from Otg._walk_named_objects(value, seen)

    def _index_config_objects(self):
        '''Maps every named object in the configuration to the object itself.'''
        index = {}
        duplicates = set()
        for name, obj in self._walk_named_objects(self._config, set()):
            if name in index and index[name] is not obj:
                duplicates.add(name)
            index[name] = obj

        if duplicates:
            raise GenieTgnError(
                'OTG configuration has more than one object named: '
                '{}'.format(', '.join(sorted(duplicates))))
        return index

    @staticmethod
    def _read_property(obj, prop):
        '''Reads a property without materialising an unset choice.'''
        properties = getattr(obj, '_properties', None)
        if isinstance(properties, dict):
            return properties.get(prop)
        return getattr(obj, prop, None)

    @staticmethod
    def _has_property(obj, prop):
        types = getattr(obj, '_TYPES', None)
        if isinstance(types, dict):
            return prop in types
        return hasattr(obj, prop)

    @classmethod
    def _is_scalar_property(cls, obj, prop, value):
        '''Return whether a named update can safely assign ``prop``.

        Configuration replacement owns nested objects and collections.  A
        partial update deliberately has the smaller contract of assigning a
        scalar leaf, so it cannot accidentally turn an OTG subtree into a
        Python dict or select a different choice branch.
        '''
        if isinstance(value, (dict, list, tuple, set)):
            return False

        current = cls._read_property(obj, prop)
        return current is None or isinstance(
            current, (str, bytes, int, float, bool))

    def get_config_object(self, name):
        '''Return the configuration object of the given OTG name

        Args:
            name ('str'): the OTG name of a port, device, interface, BGP peer,
                          route range, flow or any other named object

        Returns:
            The configuration object

        Raises:
            GenieTgnError
        '''
        self._require_api()
        index = self._index_config_objects()
        if name not in index:
            raise GenieTgnError(
                "No OTG object named '{n}' in the configuration. Configured "
                'names: {a}'.format(n=name, a=', '.join(sorted(index))))
        return index[name]

    def _planned_configuration_updates(self, updates):
        '''Validate named scalar updates before mutating the configuration.'''
        if isinstance(updates, dict):
            updates = [updates]
        if not updates:
            raise GenieTgnError('update_configuration() requires at least one '
                                'update')

        index = self._index_config_objects()
        planned = []
        for update in updates:
            properties = dict(update)
            name = properties.pop('name', None)
            planned.append(self._planned_named_update(index, name, properties,
                                                      update))
        return planned

    def _planned_named_update(self, index, name, properties, original):
        '''Resolve and validate one named scalar update.'''
        if not name:
            raise GenieTgnError(
                "each update needs a 'name' naming the OTG object to "
                'change, got: {}'.format(original))
        if name not in index:
            raise GenieTgnError(
                "No OTG object named '{n}' in the configuration. "
                'Configured names: {a}'.format(
                    n=name, a=', '.join(sorted(index))))
        if not properties:
            raise GenieTgnError(
                "update for '{}' does not change anything".format(name))

        obj = index[name]
        for prop, value in properties.items():
            # setattr would happily invent a property that the controller then
            # ignores, which reads as a pass.
            if not self._has_property(obj, prop):
                raise GenieTgnError(
                    "'{n}' ({t}) has no property '{p}'".format(
                        n=name, t=type(obj).__name__, p=prop))
            if not self._is_scalar_property(obj, prop, value):
                raise GenieTgnError(
                    "'{n}' ({t}) property '{p}' is not a scalar OTG "
                    'field'.format(n=name, t=type(obj).__name__, p=prop))
        return name, obj, properties

    def _set_planned_configuration_updates(self, planned):
        '''Apply planned scalar updates and return their previous values.'''
        previous = []
        for name, obj, properties in planned:
            for prop, value in properties.items():
                previous.append((obj, prop, self._read_property(obj, prop)))
                setattr(obj, prop, value)
                log.info("%s: %s -> %s", name, prop, value)
        return previous

    @staticmethod
    def _restore_configuration_updates(previous):
        '''Restore scalar values after a controller-side update failure.'''
        for obj, prop, value in reversed(previous):
            setattr(obj, prop, value)

    @BaseConnection.locked
    def update_configuration(self, updates, restart=True, wait_time=30,
                             stop_max_time=60):
        '''Change named objects anywhere in the OTG configuration

        Every OTG object carries a unique name, so a testcase can address any
        of them - a BGP peer, a route range, an emulated address, a port - and
        set its properties.

        Only flow rate and frame size can be changed while traffic is running;
        use update_traffic_profile() for those. Everything else requires the
        configuration to be pushed again, which restarts protocol emulation, so
        any session the device under test holds will flap.

        Args:
            updates ('list'): dicts, each carrying a 'name' plus the properties
                              to set on the object of that name
            restart ('bool'): push the configuration and bring traffic back up.
                              False leaves the change in memory for the caller
                              to push
            wait_time ('int'): seconds to wait once traffic is running again
            stop_max_time ('int'): bound on the stop that precedes the push

        Returns:
            The list of names that were updated

        Raises:
            GenieTgnError
        '''
        self._check_update_supported()

        # Resolve and validate everything before changing anything, so a typo
        # in the last update cannot leave the first one half applied.
        planned = self._planned_configuration_updates(updates)

        log.info(banner('Updating OTG configuration'))

        previous = self._set_planned_configuration_updates(planned)

        if not restart:
            self._config_dirty = True
            log.info('Configuration updated in memory; not pushed')
            return [name for name, _, _ in planned]

        try:
            log.warning('Pushing the configuration restarts protocol '
                        'emulation: emulated sessions will flap')
            self._stop_applied_configuration(stop_max_time)
            self.set_config(self._config)
            self._start_applied_configuration(wait_time)
        except Exception as err:
            self._restore_configuration_updates(previous)
            raise GenieTgnError(
                'Failed to apply the updated OTG configuration: {}'.format(
                    err)) from err

        return [name for name, _, _ in planned]

    def _configuration_payload(self, configuration):
        '''Return the archive source name and serialised OTG configuration.'''
        source = 'otg_configuration.json'
        resolved = self._resolve_configuration_source(configuration)
        if resolved is not None:
            return resolved
        if isinstance(configuration, str) and os.path.exists(configuration):
            source = configuration
            try:
                with open(configuration) as config_file:
                    return source, config_file.read()
            except OSError as err:
                raise GenieTgnError(
                    "Unable to read OTG configuration file '{c}': {e}".format(
                        c=configuration, e=err)) from err
        if isinstance(configuration, dict):
            return source, json.dumps(configuration, indent=2)
        if isinstance(configuration, (str, bytes, bytearray)):
            return source, configuration
        return source, configuration.serialize()

    def _configuration_candidate(self, configuration, payload):
        '''Deserialize non-object configuration input with the active API.'''
        if hasattr(configuration, 'serialize'):
            return configuration
        return self._deserialize_config(payload)

    def _replace_controller_configuration(self, candidate, restart,
                                          stop_max_time):
        '''Stop the old lifecycle if requested and replace the controller model.'''
        if restart:
            self._stop_applied_configuration(stop_max_time)
        self.set_config(candidate)

    @BaseConnection.locked
    def apply_configuration(self, configuration, wait_time=30, restart=True,
                            stop_max_time=60):
        '''Push an OTG configuration from a file, a dict, a string or an object

        load_configuration() reads a file; this accepts the configuration
        however the testcase happens to hold it, so a trigger datafile can
        carry the whole thing inline.

        Args:
            configuration: a file path, a dict, a JSON/YAML string, or a
                           configuration object
            wait_time ('int'): seconds to wait once traffic is running again
            restart ('bool'): bring protocols and traffic up after the push
            stop_max_time ('int'): bound on stopping an existing applied
                                   configuration before replacement

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        self._require_api()

        source, payload = self._configuration_payload(configuration)

        log.info(banner("Applying OTG configuration from '{}'".format(
            source if source != 'otg_configuration.json'
            else type(configuration).__name__)))

        archive_payload = payload.decode() if isinstance(
            payload, (bytes, bytearray)) else payload
        # Archive before parsing or a controller call. The rejected inline
        # input is as useful for diagnosis as a rejected file-based input.
        self._archive_configuration(source, archive_payload)

        # Deserialize before stopping a working configuration.  A malformed
        # inline payload must not interrupt traffic already running on the
        # controller.
        candidate = self._configuration_candidate(configuration, payload)

        try:
            self._replace_controller_configuration(candidate, restart,
                                                   stop_max_time)
        except GenieTgnError:
            raise
        except Exception as err:
            raise GenieTgnError(
                'Failed to apply the OTG configuration: {}'.format(err)) from err
        log.info('Applied OTG configuration with %s port(s), %s device(s) and '
                 '%s flow(s)', len(self._config.ports),
                 len(self._config.devices), len(self._config.flows))

        if restart:
            try:
                self._start_applied_configuration(wait_time)
            except GenieTgnError:
                raise
            except Exception as err:
                raise GenieTgnError(
                    'Failed to start the OTG configuration: {}'.format(
                        err)) from err
        return True

    @BaseConnection.locked
    def set_route_state(self, route_names=None, state='advertise',
                        wait_time=0):
        '''Advertise or withdraw emulated routes

        The one BGP change that does not need the configuration pushed again,
        so sessions stay up and traffic keeps running across it.

        Args:
            route_names ('list'): OTG names of route ranges, all of them when
                                  omitted
            state ('str'): 'advertise' or 'withdraw'
            wait_time ('int'): seconds to wait after the controller applies it

        Returns:
            The route names acted on

        Raises:
            GenieTgnError
        '''
        api = self._require_api()

        control = api.control_state()
        route = control.protocol.route
        if state not in (route.ADVERTISE, route.WITHDRAW):
            raise GenieTgnError(
                "Route state must be '{a}' or '{w}', got '{s}'".format(
                    a=route.ADVERTISE, w=route.WITHDRAW, s=state))

        if isinstance(route_names, str):
            route_names = [route_names]
        if not route_names:
            route_names = self._default_route_names()
        if not route_names:
            raise GenieTgnError('No route ranges in the OTG configuration')

        log.info(banner('Setting %d route range(s) to %s' % (len(route_names),
                                                             state)))
        control.choice = control.PROTOCOL
        control.protocol.choice = control.protocol.ROUTE
        route.names = list(route_names)
        route.state = state

        try:
            api.set_control_state(control)
        except Exception as err:
            raise GenieTgnError(
                'Failed to {s} routes {r}: {e}'.format(
                    s=state, r=', '.join(route_names), e=err)) from err

        self._wait(wait_time, 'after changing route state')
        return list(route_names)

    # -------------------------------------------------------------------------
    # Packet capture
    # -------------------------------------------------------------------------

    def _capture_state(self, port_names, state):
        api = self._require_api()
        control = api.control_state()
        control.choice = control.PORT
        control.port.choice = control.port.CAPTURE
        control.port.capture.state = state
        if port_names:
            control.port.capture.port_names = list(port_names)
        api.set_control_state(control)

    def start_capture(self, port_names=None):
        '''Start the OTG captures of the given ports (default: all).'''
        self._capture_state(port_names, 'start')

    def stop_capture(self, port_names=None):
        '''Stop the OTG captures of the given ports (default: all).'''
        self._capture_state(port_names, 'stop')

    def save_capture(self, port_name, path=None):
        '''Fetch the capture of a port and write it to a file.

        Args:
            port_name ('str'): OTG port name
            path ('str'): destination; default: the pyATS runinfo directory
                          (or the current directory) as
                          ``<device>-<port>.pcap``
        Returns:
            the path of the written file
        '''
        api = self._require_api()
        request = api.capture_request()
        request.port_name = port_name
        data = api.get_capture(request)
        if hasattr(data, 'read'):
            data = data.read()
        if path is None:
            path = _artifact_path(
                getattr(runtime, 'directory', None) or '.',
                '{d}-{p}.pcap', d=getattr(self.device, 'name', 'tgn'),
                p=port_name)
        with open(path, 'wb') as capture_file:
            capture_file.write(data)
        log.info('Capture of port %s saved to %s (%d bytes)', port_name, path,
                 len(data))
        return path

    # -------------------------------------------------------------------------
    # Packet capture, IxiaNative call signatures
    #
    # IxNetwork captures per vport and separates the hardware (data) capture
    # from the software (control) one. OTG captures per port and makes no
    # such split, so both pairs below drive the one OTG capture of the port
    # and `pcap_type` only selects which counter or file name is reported.
    # -------------------------------------------------------------------------

    @staticmethod
    def _capture_ports(ports):
        '''Port names from an IxiaNative 'p1, p2' string or a list.'''
        if isinstance(ports, str):
            return [name.strip() for name in ports.split(',') if name.strip()]
        return [str(name) for name in ports or []]

    def _capture_for_port(self, port_name, create=False):
        '''The OTG capture covering a port, optionally adding one.'''
        self._require_api()
        for capture in self._config.captures:
            if port_name in list(capture.port_names or []):
                return capture
        if not create:
            return None
        capture = self._config.captures.add()
        capture.name = 'capture_{}'.format(port_name)
        capture.port_names = [port_name]
        self._config_dirty = True
        return capture

    def _set_capture_ports(self, ports, enabled, kind):
        for port_name in self._capture_ports(ports):
            capture = self._capture_for_port(port_name, create=enabled)
            if enabled:
                log.info("Enabling %s packet capture on port '%s'", kind,
                         port_name)
                continue
            if capture is None:
                continue
            log.info("Disabling %s packet capture on port '%s'", kind,
                     port_name)
            remaining = [name for name in capture.port_names
                         if name != port_name]
            if remaining:
                capture.port_names = remaining
            else:
                # OTG refuses a capture without ports, so it goes
                self._drop_capture(capture.name)
            self._config_dirty = True
        return True

    def _drop_capture(self, name):
        '''Remove the named capture from the configuration.'''
        kept = [capture for capture in self._config.captures
                if capture.name != name]
        self._config.captures.clear()
        for capture in kept:
            self._config.captures.append(capture)

    @BaseConnection.locked
    def enable_data_packet_capture(self, ports):
        '''Enable data packet capture on ports specified

        Args:
            ports ('str'/'list'): port names, as 'p1, p2' or a list

        Returns:
            True
        '''
        return self._set_capture_ports(ports, True, 'data')

    @BaseConnection.locked
    def disable_data_packet_capture(self, ports):
        '''Disable data packet capture on ports specified'''
        return self._set_capture_ports(ports, False, 'data')

    @BaseConnection.locked
    def enable_control_packet_capture(self, ports):
        '''Enable control packet capture on ports specified

        OTG has one capture per port, so this is the same capture
        enable_data_packet_capture() controls.
        '''
        return self._set_capture_ports(ports, True, 'control')

    @BaseConnection.locked
    def disable_control_packet_capture(self, ports):
        '''Disable control packet capture on ports specified'''
        return self._set_capture_ports(ports, False, 'control')

    @BaseConnection.locked
    def start_packet_capture(self, capture_time=60):
        '''Start capturing packets for a specified amount of time

        Args:
            capture_time ('int'): seconds to capture before returning

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        log.info(banner('Starting OTG packet capture'))
        try:
            self.start_capture()
        except Exception as err:
            raise GenieTgnError(
                'Unable to start packet capture: {}'.format(err)) from err
        self._wait(capture_time, 'after starting packet capture')
        return True

    @BaseConnection.locked
    def stop_packet_capture(self):
        '''Stop capturing packets

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        log.info(banner('Stopping OTG packet capture'))
        try:
            self.stop_capture()
        except Exception as err:
            raise GenieTgnError(
                'Unable to stop packet capture: {}'.format(err)) from err
        return True

    def _capture_bytes(self, port_name):
        api = self._require_api()
        request = api.capture_request()
        request.port_name = port_name
        data = api.get_capture(request)
        if hasattr(data, 'read'):
            data = data.read()
        return data

    @BaseConnection.locked
    def get_packet_capture_count(self, port_name, pcap_type):
        '''Get the total count of packets captured during packet capture

        OTG reports no running capture counter, so the capture is fetched
        and its frames counted. A port captures data and control frames
        together, so both pcap_type values return that one count.

        Args:
            port_name ('str'): OTG port name
            pcap_type ('str'): 'data' or 'control'

        Returns:
            'int': frames in the capture

        Raises:
            GenieTgnError
        '''
        if pcap_type not in ('data', 'control'):
            raise GenieTgnError(
                "pcap_type must be 'data' or 'control', got "
                "'{}'".format(pcap_type))
        log.info("Getting total count of %s packets on port '%s'", pcap_type,
                 port_name)
        try:
            count = _count_pcap_frames(self._capture_bytes(port_name))
        except GenieTgnError:
            raise
        except Exception as err:
            raise GenieTgnError(
                'Error while counting packets captured on port '
                "'{p}': {e}".format(p=port_name, e=err)) from err
        log.info("Port '%s' captured %d packet(s)", port_name, count)
        return count

    @BaseConnection.locked
    def get_packet_capture_data(self, port_name):
        '''Return the packets collected on a port

        IxNetwork walks the decoded header stack of one packet; OTG returns
        the capture itself, so this returns its bytes for the caller to
        decode.

        Args:
            port_name ('str'): OTG port name

        Returns:
            'bytes': the capture in pcap/pcapng form

        Raises:
            GenieTgnError
        '''
        log.info("Getting packet capture data on port '%s'", port_name)
        try:
            data = self._capture_bytes(port_name)
        except Exception as err:
            raise GenieTgnError(
                'Error while getting the packet capture of port '
                "'{p}': {e}".format(p=port_name, e=err)) from err
        log.info("Port '%s' capture is %d byte(s), %d packet(s)", port_name,
                 len(data), _count_pcap_frames(data))
        return data

    @BaseConnection.locked
    def save_packet_capture_file(self, port_name, pcap_type, filename,
                                 directory=None):
        '''Save packet capture file as specified filename to desired location

        Args:
            port_name ('str'): OTG port name
            pcap_type ('str'): 'data' or 'control', used in the file name
            filename ('str'): base name of the file to write
            directory ('str'): destination directory; default: the pyATS
                               runinfo directory. IxiaNative defaults to a
                               directory on the IxNetwork host, which has no
                               meaning here: the controller sends the
                               capture back and it is written locally.

        Returns:
            'str': the path of the written file

        Raises:
            GenieTgnError
        '''
        if pcap_type not in ('data', 'control'):
            raise GenieTgnError(
                "pcap_type must be 'data' or 'control', got "
                "'{}'".format(pcap_type))
        if directory is None:
            directory = getattr(runtime, 'directory', None) or '.'
        path = _artifact_path(
            directory, '{p}_{t}_{f}.pcap', p=port_name,
            t={'data': 'HW', 'control': 'SW'}[pcap_type], f=filename)
        log.info(banner('Saving OTG packet capture file'))
        return self.save_capture(port_name, path)

    @BaseConnection.locked
    def export_packet_capture_file(self, src_file, dest_file='ixia.pcap'):
        '''Copy a saved packet capture into the runtime logs

        Args:
            src_file ('str'): a file written by save_packet_capture_file()
            dest_file ('str'): name to give it in the runtime directory;
                               path separators are percent-encoded

        Returns:
            'str': the path of the exported file

        Raises:
            GenieTgnError
        '''
        destination = _artifact_path(
            getattr(runtime, 'directory', None) or '.', '{f}', f=dest_file)
        log.info('Exporting packet capture file...')
        try:
            if os.path.abspath(src_file) != os.path.abspath(destination):
                copyfile(src_file, destination)
        except Exception as err:
            raise GenieTgnError(
                "Unable to export the packet capture file to '{d}': "
                '{e}'.format(d=destination, e=err)) from err
        log.info('Successfully exported PCAP capture file to %s', destination)
        return destination

    # -------------------------------------------------------------------------
    # Emulated BGP
    # -------------------------------------------------------------------------

    def _require_bgp_support(self):
        '''Emulated BGP is a controller feature; the simulator has none.'''
        api = self._require_api()
        if not hasattr(api.control_state().protocol, 'bgp'):
            raise GenieTgnError(
                'Emulated BGP requires the snappi SDK and an OTG controller '
                "that supports it; it is not available with transport='mock'.")
        return api

    def _bgp_metrics_names(self, choice, peers):
        '''Map IxNetwork device-group metrics to unambiguous OTG peers.'''
        if str(self.ext or '').lower() != 'ixnetwork':
            return peers, {name: name for name in peers}

        peer_type = 'BgpV4Peer' if choice == 'bgpv4' else 'BgpV6Peer'
        devices = []
        names = {}
        for device in self._config.devices:
            configured = [name for name, obj in
                          self._walk_named_objects(device, set())
                          if type(obj).__name__ == peer_type]
            if not set(configured).intersection(peers):
                continue
            # snappi-ixnetwork filters and labels protocol statistics by
            # device group, despite calling the request field peer_names.
            # A group containing several peers cannot identify each one.
            if len(configured) != 1 or device.name.lower() in names:
                raise GenieTgnError(
                    'IxNetwork BGP metrics cannot identify the peers of '
                    "device '{}'; use one peer of each family per device "
                    'with names distinct without regard to case'.format(
                        device.name))
            devices.append(device.name)
            # The extension lowercases string-valued metrics, even names.
            names[device.name.lower()] = configured[0]
        return devices, names

    def _bgp_family_metrics(self, api, choice, peers):
        '''Request one address family and normalize its metric names.'''
        query_names, metric_names = self._bgp_metrics_names(choice, peers)
        request = api.metrics_request()
        request.choice = choice
        getattr(request, choice).peer_names = query_names
        response = api.get_metrics(request)
        result = {}
        for metric in getattr(response, '{}_metrics'.format(choice)):
            key = metric.name.lower() if str(
                self.ext or '').lower() == 'ixnetwork' else metric.name
            name = metric_names.get(key)
            if name is None:
                continue
            result[name] = {
                key: getattr(metric, key, None)
                for key in metric._TYPES if key != 'name'}
        return result

    def get_bgp_metrics(self, peers=None):
        '''Return BGP session metrics keyed by OTG peer name

        Args:
            peers ('list'): OTG BGP peer names, all of them when omitted

        Returns:
            dict of peer name -> {metric name: value}

        Raises:
            GenieTgnError
        '''
        api = self._require_bgp_support()
        if isinstance(peers, str):
            peers = [peers]
        configured = self._bgp_peer_names()
        known = configured['bgpv4'] + configured['bgpv6']
        unknown = [name for name in peers or [] if name not in known]
        if unknown:
            raise GenieTgnError(
                'BGP peers not found in the OTG configuration: {}'.format(
                    ', '.join(unknown)))

        result = {}
        for choice, names in configured.items():
            wanted = [name for name in names if not peers or name in peers]
            if not wanted:
                continue
            result.update(self._bgp_family_metrics(api, choice, wanted))
        return result

    def verify_bgp_sessions(self, peers=None, state='up', check_eor=False,
                            max_time=120, interval=10):
        '''Wait until the emulated BGP sessions reach a state

        Args:
            peers ('list'): OTG BGP peer names, all of them when omitted
            state ('str'): 'up' or 'down'
            check_eor ('bool'): with state 'up', also require at least one
                                End-of-RIB from the device under test
            max_time ('int'): seconds to keep checking
            interval ('int'): seconds between checks

        Returns:
            The metrics of the verified peers

        Raises:
            GenieTgnError
        '''
        if state not in ('up', 'down'):
            raise GenieTgnError("state must be 'up' or 'down', got "
                                "'{}'".format(state))
        if isinstance(peers, str):
            peers = [peers]
        configured = self._bgp_peer_names()
        expected = peers or configured['bgpv4'] + configured['bgpv6']
        if not expected:
            raise GenieTgnError('No BGP peers in the OTG configuration')
        log.info(banner('Verifying BGP sessions are {}'.format(state)))
        deadline = time.time() + float(max_time)
        while True:
            metrics = self.get_bgp_metrics(peers)
            failing = sorted(
                name for name, values in metrics.items()
                if values.get('session_state') != state or (
                    check_eor and state == 'up'
                    and not values.get('end_of_rib_received')))
            missing = sorted(set(expected) - set(metrics))
            if not failing and not missing:
                log.info('BGP sessions %s are %s', ', '.join(sorted(metrics)),
                         state)
                return metrics
            if time.time() >= deadline:
                raise GenieTgnError(
                    'BGP sessions not {s} after {t}s: {p}'.format(
                        s=state, t=max_time,
                        p=', '.join(failing + missing)))
            log.info('Waiting for BGP sessions %s to be %s',
                     ', '.join(failing + missing), state)
            time.sleep(float(interval))

    @BaseConnection.locked
    def set_bgp_peer_state(self, peers=None, state='up', wait_time=0):
        '''Bring emulated BGP peers up or down without a configuration push

        Args:
            peers ('list'): OTG BGP peer names, all of them when omitted
            state ('str'): 'up' or 'down'
            wait_time ('int'): seconds to wait afterwards

        Returns:
            The peer names acted on

        Raises:
            GenieTgnError
        '''
        if state not in ('up', 'down'):
            raise GenieTgnError(
                "BGP peer state must be 'up' or 'down', got {!r}".format(state))
        if str(self.ext or '').lower() == 'ixnetwork':
            raise GenieTgnError(
                'The snappi-ixnetwork extension does not implement BGP '
                'peer state control; use start_all_protocols() or '
                'stop_all_protocols() for whole-controller control')
        api = self._require_bgp_support()
        if isinstance(peers, str):
            peers = [peers]
        configured = self._bgp_peer_names()
        known = configured['bgpv4'] + configured['bgpv6']
        peers = list(peers or known)
        if not peers:
            raise GenieTgnError('No BGP peers in the OTG configuration')
        unknown = sorted(set(peers) - set(known))
        if unknown:
            raise GenieTgnError(
                'BGP peers not configured: {}'.format(', '.join(unknown)))

        control = api.control_state()
        control.choice = control.PROTOCOL
        control.protocol.choice = control.protocol.BGP
        control.protocol.bgp.peers.peer_names = peers
        control.protocol.bgp.peers.state = state
        log.info(banner('Setting BGP peer(s) {} {}'.format(
            ', '.join(peers), state)))
        try:
            api.set_control_state(control)
        except Exception as err:
            raise GenieTgnError('Failed to set BGP peers {p} {s}: {e}'.format(
                p=', '.join(peers), s=state, e=err)) from err
        self._wait(wait_time, 'after changing BGP peer state')
        return peers

    @staticmethod
    def _traffic_profile_properties(update, rate, size):
        '''Select the controller fields affected by a live flow update.'''
        properties = []
        if rate is not None:
            properties.append(update.flows.RATE)
        if size is not None:
            properties.append(update.flows.SIZE)
        return properties

    def _traffic_profile_targets(self, traffic_streams):
        '''Resolve live-update flow names against the current OTG model.'''
        configured = {flow.name: flow for flow in self._config.flows}
        if not configured:
            raise GenieTgnError(
                'Cannot update traffic profile: no OTG flows are configured')

        requested = traffic_streams or list(configured)
        if isinstance(requested, str):
            requested = [requested]
        unknown = [name for name in requested if name not in configured]
        if unknown:
            raise GenieTgnError(
                'Traffic streams not found in OTG configuration: '
                '{}'.format(', '.join(sorted(unknown))))
        return configured, requested

    @staticmethod
    def _traffic_profile_description(rate, size, rate_attribute='pps'):
        '''Format the properties being modified for the operation log.'''
        descriptions = []
        if rate is not None:
            descriptions.append('rate {r} {u}'.format(r=rate,
                                                      u=rate_attribute))
        if size is not None:
            descriptions.append('frame size {} bytes'.format(size))
        return ', '.join(descriptions)

    def _set_traffic_profile_values(self, update, configured, requested,
                                    rate, size, rate_attribute='pps'):
        '''Change live flow values and populate the controller update request.

        rate_attribute selects which OTG rate choice the value belongs to:
        'pps' for a packet rate, 'percentage' for a line rate, or one of
        the bit-rate choices. Setting the attribute is what switches the
        flow onto that choice.
        '''
        previous = {}
        description = self._traffic_profile_description(rate, size,
                                                        rate_attribute)
        for name in requested:
            flow = configured[name]
            # The whole rate and size, choice included: reading a choice
            # property switches the flow onto it, so a value read on its own
            # would not be the one to put back.
            previous[name] = (flow.rate.serialize(flow.rate.DICT),
                              flow.size.serialize(flow.size.DICT))
            if rate is not None:
                setattr(flow.rate, rate_attribute, rate)
            if size is not None:
                flow.size.fixed = size
            update.flows.flows.append(flow)
            log.info("Traffic stream '%s' updated to %s", name, description)
        return previous

    @staticmethod
    def _restore_traffic_profile_values(configured, previous):
        '''Restore in-memory flow values to the controller-accepted profile.'''
        for name, (old_rate, old_size) in previous.items():
            flow = configured[name]
            flow.rate.deserialize(old_rate)
            flow.size.deserialize(old_size)

    def _rollback_traffic_profile(self, api, properties, configured,
                                  previous):
        '''Best-effort controller rollback after a live update is rejected.'''
        self._restore_traffic_profile_values(configured, previous)
        rollback = api.config_update()
        rollback.flows.property_names = properties
        for name in previous:
            rollback.flows.flows.append(configured[name])
        try:
            api.update_flows(rollback.flows)
        except Exception as rollback_err:
            log.error("Unable to restore the previous OTG traffic profile "
                      "after update failure: %s", rollback_err)

    @BaseConnection.locked
    def update_traffic_profile(self, traffic_streams=None, rate=None,
                               size=None, wait_time=0, rate_attribute='pps'):
        '''Change the rate and/or frame size of configured traffic streams

        The controller applies the change to the streams in place, so traffic
        keeps running and the counters keep accumulating: there is no reload
        and no protocol restart. Rate and frame size are the only properties
        OTG allows to be changed this way.

        Args:
            traffic_streams ('list'): stream names to update, every stream
                                      when omitted
            rate ('int'): new transmit rate, in the unit named by
                          rate_attribute
            size ('int'): new fixed frame size in bytes
            wait_time ('int'): seconds to wait after the update is applied
            rate_attribute ('str'): the OTG rate choice the rate belongs to:
                                    'pps', 'percentage', 'bps', 'kbps',
                                    'mbps' or 'gbps'

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        api = self._require_api()

        if rate is None and size is None:
            raise GenieTgnError('update_traffic_profile() requires a rate, '
                                'a size, or both')

        if rate is not None and rate_attribute not in RATE_ATTRIBUTES:
            raise GenieTgnError(
                'rate_attribute must be one of {}, got {!r}'.format(
                    ', '.join(RATE_ATTRIBUTES), rate_attribute))

        configured, requested = self._traffic_profile_targets(traffic_streams)
        # Only streams the controller already holds can be updated in place.
        self.translation_engine.commit()

        log.info(banner('Updating OTG traffic profile'))

        update = api.config_update()
        properties = self._traffic_profile_properties(update, rate, size)
        update.flows.property_names = properties

        # The request carries the live flow objects, so the in-memory
        # configuration moves with the controller and the expected rate used
        # by check_traffic_loss() stays honest.
        previous = self._set_traffic_profile_values(update, configured,
                                                    requested, rate, size,
                                                    rate_attribute)

        try:
            api.update_flows(update.flows)
        except Exception as err:
            self._rollback_traffic_profile(api, properties, configured,
                                           previous)
            raise GenieTgnError(
                'Failed to update the OTG traffic profile: {}'.format(
                    err)) from err

        self._wait(wait_time, 'after updating the traffic profile')
        return True

    # -------------------------------------------------------------------------
    # Rate and frame size, IxiaNative call signatures
    #
    # IxNetwork stops traffic, edits the stream, regenerates and restarts it,
    # which is why these take four timings. OTG updates a running flow in
    # place, so only start_traffic and start_traffic_time are acted on; the
    # other timings are accepted and ignored so existing call sites keep
    # working. IxNetwork also splits a traffic item into flow groups, which
    # OTG has no equivalent for: a flow group names an OTG flow.
    # -------------------------------------------------------------------------

    # IxiaNative's -bitRateUnitsType values, as OTG rate choices.
    _BIT_RATE_UNITS = {'bps': ('bps', 1), 'Kbps': ('kbps', 1),
                       'Mbps': ('mbps', 1), 'Bps': ('bps', 8),
                       'KBps': ('kbps', 8), 'MBps': ('mbps', 8)}

    def _rate_target(self, traffic_stream, flow_group=''):
        '''The OTG flow a traffic stream plus flow group refers to.'''
        return flow_group or traffic_stream

    def _update_rate(self, traffic_stream, rate, flow_group, rate_attribute,
                     start_traffic, start_traffic_time):
        name = self._rate_target(traffic_stream, flow_group)
        self.update_traffic_profile(traffic_streams=[name], rate=rate,
                                    rate_attribute=rate_attribute)
        self._start_updated_flow(name, start_traffic, start_traffic_time)
        return True

    def _start_updated_flow(self, name, start_traffic, wait_time):
        '''Keep live edits running without issuing another START request.'''
        if not start_traffic:
            return
        state = self._flow_transmit_states().get(name)
        if state == 'stopped':
            self.start_traffic(wait_time=wait_time, traffic_streams=[name])
        elif state == 'started':
            self._wait(wait_time, 'after updating a running traffic stream')
        else:
            raise GenieTgnError(
                "Cannot establish transmit state for flow '{n}': {s}".format(
                    n=name, s=state or 'missing metrics'))

    def _flow_by_name(self, name):
        '''The configured OTG flow of that name.'''
        self._require_api()
        for flow in self._config.flows:
            if flow.name == name:
                return flow
        raise GenieTgnError(
            "Traffic stream '{n}' not found in OTG configuration: "
            '{a}'.format(n=name,
                         a=', '.join(sorted(f.name for f in
                                            self._config.flows)) or 'none'))

    @BaseConnection.locked
    def set_packet_rate(self, traffic_stream, rate, flow_group='',
                        stop_traffic_time=15, generate_traffic_time=15,
                        apply_traffic_time=15, start_traffic=True,
                        start_traffic_time=15):
        '''Set the packet rate for given traffic stream or given flow group

        Args:
            traffic_stream ('str'): OTG flow name
            rate ('int'): packets per second
            flow_group ('str'): OTG flow name, when it differs from the
                                traffic stream
            start_traffic ('bool'): start the stream after the update
            start_traffic_time ('int'): seconds to wait after starting

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        return self._update_rate(traffic_stream, rate, flow_group, 'pps',
                                 start_traffic, start_traffic_time)

    @BaseConnection.locked
    def set_line_rate(self, traffic_stream, rate, flow_group='',
                      stop_traffic_time=15, generate_traffic_time=15,
                      apply_traffic_time=15, start_traffic=True,
                      start_traffic_time=15):
        '''Set the line rate for given traffic stream or given flow group

        Args:
            traffic_stream ('str'): OTG flow name
            rate ('int'): percentage of line rate
            flow_group ('str'): OTG flow name, when it differs from the
                                traffic stream

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        return self._update_rate(traffic_stream, rate, flow_group,
                                 'percentage', start_traffic,
                                 start_traffic_time)

    @BaseConnection.locked
    def set_layer2_bit_rate(self, traffic_stream, rate, rate_unit,
                            flow_group='', stop_traffic_time=15,
                            generate_traffic_time=15, apply_traffic_time=15,
                            start_traffic=True, start_traffic_time=15):
        '''Set the Layer2 bit rate for given traffic stream or flow group

        Args:
            traffic_stream ('str'): OTG flow name
            rate ('int'): the rate, in rate_unit
            rate_unit ('str'): bps, Kbps, Mbps, Bps, KBps or MBps
            flow_group ('str'): OTG flow name, when it differs from the
                                traffic stream

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        if rate_unit not in self._BIT_RATE_UNITS:
            raise GenieTgnError(
                "rate_unit must be one of {u}, got '{r}'".format(
                    u=', '.join(sorted(self._BIT_RATE_UNITS)), r=rate_unit))
        # OTG counts bits, so a byte rate is the same number of bits x 8.
        attribute, multiplier = self._BIT_RATE_UNITS[rate_unit]
        return self._update_rate(traffic_stream, rate * multiplier,
                                 flow_group, attribute, start_traffic,
                                 start_traffic_time)

    @BaseConnection.locked
    def set_packet_size_fixed(self, traffic_stream, packet_size,
                              stop_traffic_time=15, generate_traffic_time=15,
                              apply_traffic_time=15, start_traffic=True,
                              start_traffic_time=15):
        '''Set the packet size for given traffic stream

        Args:
            traffic_stream ('str'): OTG flow name
            packet_size ('int'): fixed frame size in bytes

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        self.update_traffic_profile(traffic_streams=[traffic_stream],
                                    size=packet_size)
        self._start_updated_flow(traffic_stream, start_traffic,
                                start_traffic_time)
        return True

    def _get_rate(self, traffic_stream, flow_group, rate_attribute):
        flow = self._flow_by_name(self._rate_target(traffic_stream,
                                                    flow_group))
        choice = getattr(flow.rate, 'choice', None)
        if choice is not None and choice != rate_attribute:
            raise GenieTgnError(
                "Traffic stream '{n}' is configured by {c}, not {a}".format(
                    n=flow.name, c=choice, a=rate_attribute))
        return getattr(flow.rate, rate_attribute)

    @BaseConnection.locked
    def get_packet_rate(self, traffic_stream, flow_group=''):
        '''Returns the packet rate for given traffic stream or flow group'''
        return self._get_rate(traffic_stream, flow_group, 'pps')

    @BaseConnection.locked
    def get_line_rate(self, traffic_stream, flow_group=''):
        '''Returns the line rate for given traffic stream or flow group'''
        return self._get_rate(traffic_stream, flow_group, 'percentage')

    @BaseConnection.locked
    def get_layer2_bit_rate(self, traffic_stream, flow_group=''):
        '''Returns the layer2 bit rate for given traffic stream or flow group

        The value is in the unit the flow is configured with, which OTG
        reports through the rate choice.
        '''
        flow = self._flow_by_name(self._rate_target(traffic_stream,
                                                    flow_group))
        choice = getattr(flow.rate, 'choice', None)
        if choice not in ('bps', 'kbps', 'mbps', 'gbps'):
            raise GenieTgnError(
                "Traffic stream '{n}' is not configured by a bit rate "
                '(rate choice {c})'.format(n=flow.name, c=choice))
        return getattr(flow.rate, choice)

    @BaseConnection.locked
    def get_packet_size(self, traffic_stream):
        '''Returns the packet size for given traffic stream'''
        return self._flow_by_name(traffic_stream).size.fixed

    # -------------------------------------------------------------------------
    # Per-stream control, IxiaNative call signatures
    # -------------------------------------------------------------------------

    @BaseConnection.locked
    def start_traffic_stream(self, traffic_stream, check_stream=True,
                             wait_time=15, max_time=180):
        '''Start specific traffic stream on the traffic generator

        Args:
            traffic_stream ('str'): OTG flow name
            check_stream ('bool'): verify the stream is transmitting
            wait_time ('int'): seconds to wait after starting
            max_time ('int'): seconds to wait for the stream to transmit

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        self._flow_by_name(traffic_stream)
        self.start_traffic(wait_time=wait_time,
                           traffic_streams=[traffic_stream])
        if check_stream:
            self._check_stream_transmitting(traffic_stream, max_time)
        return True

    def _flow_transmit_states(self):
        '''Whether each flow is transmitting, as the controller reports it.

        The flow metrics carry this; the statistics views do not, so it is
        read from the metrics rather than inferred from a local flag.
        '''
        api = self._require_api()
        request = api.metrics_request()
        request.choice = request.FLOW
        return {metric.name: str(getattr(metric, 'transmit', '')).lower()
                for metric in api.get_metrics(request).flow_metrics}

    def _check_stream_transmitting(self, traffic_stream, max_time):
        '''Wait for a started stream to actually send frames.'''
        deadline = time.time() + float(max_time)
        previous = None
        while True:
            row = self.get_stats(
                view=FLOW_STATISTICS).get(traffic_stream, {})
            try:
                frames = float(row.get(TX_FRAMES))
            except (TypeError, ValueError):
                frames = None
            state = self._flow_transmit_states().get(traffic_stream)
            valid = (frames is not None and math.isfinite(frames)
                     and frames >= 0 and state == 'started')
            if (valid and previous is not None and frames > previous):
                log.info("Traffic stream '%s' is transmitting",
                         traffic_stream)
                return True
            # Missing/invalid statistics must not become a zero baseline
            # against which historical counters could look like new traffic.
            previous = frames if valid else None
            if time.time() > deadline:
                raise GenieTgnError(
                    "Traffic stream '{s}' sent no new frames within {t} "
                    'seconds of being started'.format(s=traffic_stream,
                                                      t=max_time))
            time.sleep(min(1, max(0, deadline - time.time())))

    @BaseConnection.locked
    def stop_traffic_stream(self, traffic_stream, wait_time=15):
        '''Stop specific traffic stream on the traffic generator

        Args:
            traffic_stream ('str'): OTG flow name
            wait_time ('int'): seconds to wait after stopping

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        self._flow_by_name(traffic_stream)
        self.stop_traffic(wait_time=wait_time,
                          traffic_streams=[traffic_stream])
        return True

    @BaseConnection.locked
    def get_flow_group_names(self, traffic_stream):
        '''Returns the flow group names of the given traffic stream

        IxNetwork splits a traffic item into flow groups. OTG has no such
        level, so a stream is its own single group and this returns its
        name, which keeps a caller's iteration over groups working.

        Args:
            traffic_stream ('str'): OTG flow name

        Returns:
            'list': the flow group names

        Raises:
            GenieTgnError
        '''
        return [self._flow_by_name(traffic_stream).name]

    @BaseConnection.locked
    def start_flow_group(self, traffic_stream, flow_group, wait_time=15):
        '''Start given flow group of a traffic stream

        A flow group names an OTG flow; see get_flow_group_names().
        '''
        return self.start_traffic_stream(
            self._rate_target(traffic_stream, flow_group),
            check_stream=False, wait_time=wait_time)

    @BaseConnection.locked
    def stop_flow_group(self, traffic_stream, flow_group, wait_time=15):
        '''Stop given flow group of a traffic stream

        A flow group names an OTG flow; see get_flow_group_names().
        '''
        return self.stop_traffic_stream(
            self._rate_target(traffic_stream, flow_group),
            wait_time=wait_time)

    @BaseConnection.locked
    def check_flow_groups_loss(self, traffic_streams=None, max_outage=120,
                               loss_tolerance=15, rate_tolerance=5,
                               csv_windows_path=None, csv_file_name=None,
                               verbose=False, display=True,
                               export_to_filename='', remove_vlan=False):
        '''Check traffic loss for the flow groups of the given streams

        OTG reports per-flow metrics natively, so this is check_traffic_loss()
        over the flows of those streams. The CSV arguments are IxNetwork's
        way of reaching the same numbers and are accepted but unused.

        Returns:
            the check_traffic_loss() result

        Raises:
            GenieTgnError
        '''
        return self.check_traffic_loss(traffic_streams=traffic_streams,
                                       max_outage=max_outage,
                                       loss_tolerance=loss_tolerance,
                                       rate_tolerance=rate_tolerance)

    @BaseConnection.locked
    def check_ecmp_traffic_loss(self, ecmp_traffic_items, tolerance=0.05,
                                clear_stats=False, clear_stats_time=30,
                                disable_tracking=False,
                                disable_port_pair=False, check_iteration=5,
                                check_interval=60, pre_check_wait=None,
                                raise_on_loss=True, **kwargs):
        '''Check that each ECMP stream receives what it transmitted

        Traffic spread over ECMP paths arrives on several receive ports, so
        the check is the stream's transmitted frames against the sum it
        received, within a fractional tolerance.

        Args:
            ecmp_traffic_items ('list'): stream names to treat as ECMP
            tolerance ('float'): allowed fractional difference, 0.05 is 5%
            clear_stats ('bool'): clear statistics before checking
            clear_stats_time ('int'): seconds to wait after clearing
            check_iteration ('int'): attempts before failing
            check_interval ('int'): seconds between attempts
            pre_check_wait ('int'): seconds to wait before the first check
            raise_on_loss ('bool'): raise when a stream is still outside
                                    tolerance on the last attempt

        Returns:
            'dict': {stream: (tx_frames, rx_frames, within_tolerance)}

        Raises:
            GenieTgnError
        '''
        self._require_api()
        if isinstance(ecmp_traffic_items, str):
            ecmp_traffic_items = [ecmp_traffic_items]
        iterations = int(check_iteration)
        if iterations < 1:
            raise GenieTgnError(
                "'check_iteration' must be greater than zero, got "
                '{}'.format(check_iteration))

        self._wait(pre_check_wait, 'before the ECMP traffic check')
        if clear_stats:
            self.clear_statistics(wait_time=clear_stats_time)

        results, failed = {}, []
        for attempt in range(iterations):
            if attempt:
                self._wait(check_interval, 'before retrying the ECMP check')
            results, failed = self._check_ecmp_once(ecmp_traffic_items,
                                                    tolerance)
            if not failed:
                log.info('ECMP traffic loss is within tolerance for every '
                         'ECMP traffic item')
                return results
        if raise_on_loss:
            raise GenieTgnError(
                'Unexpected ECMP traffic loss is observed for traffic '
                'item(s): {}'.format(', '.join(failed)))
        return results

    def _check_ecmp_once(self, ecmp_traffic_items, tolerance):
        '''One pass of the ECMP check over the current flow statistics.

        Returns:
            'tuple': ({stream: (tx_frames, rx_frames, within_tolerance)},
                      the streams outside tolerance)
        '''
        stats = self.get_stats(view=FLOW_STATISTICS)
        results, failed = {}, []
        for name in ecmp_traffic_items:
            row = stats.get(name)
            if row is None:
                raise GenieTgnError(
                    "ECMP traffic item '{n}' is not a configured OTG "
                    'flow'.format(n=name))
            tx = _as_float(row.get(TX_FRAMES))
            rx = _as_float(row.get(RX_FRAMES))
            within = tx > 0 and abs(tx - rx) <= tx * float(tolerance)
            results[name] = (tx, rx, within)
            if within:
                log.info('PASS: ECMP check for %r: Tx=%d, Rx=%d, '
                         'tolerance=%.1f%%', name, tx, rx,
                         float(tolerance) * 100)
            else:
                log.error('FAIL: ECMP check for %r: Tx=%d, Rx=%d, '
                          'tolerance=%.1f%%', name, tx, rx,
                          float(tolerance) * 100)
                failed.append(name)
        return results, failed

    # -------------------------------------------------------------------------
    # Statistics, IxiaNative call signatures
    #
    # IxNetwork reads numbers out of named statistics views and pages; OTG
    # reports flow and port metrics directly, so these are views onto
    # get_stats(). The CSV arguments name a path on the IxNetwork host and
    # are accepted but unused: there is no remote host to write to.
    # -------------------------------------------------------------------------

    # The statistics 'views' OTG can serve, by the names Ixia uses.
    _STATISTICS_VIEWS = (FLOW_STATISTICS, TRAFFIC_ITEM_STATISTICS,
                         PORT_STATISTICS, 'GENIE')

    @BaseConnection.locked
    def get_all_statistics_views(self):
        '''Returns the statistics views available on this traffic generator

        Returns:
            'list': the view names get_stats() accepts
        '''
        return list(self._STATISTICS_VIEWS)

    def _statistics_row(self, traffic_stream, view):
        stats = self.get_stats(view=view)
        row = stats.get(traffic_stream)
        if row is None:
            raise GenieTgnError(
                "Traffic stream '{s}' not found in '{v}': {a}".format(
                    s=traffic_stream, v=view,
                    a=', '.join(sorted(stats)) or 'no streams'))
        return row

    @staticmethod
    def _statistics_field(row, field, traffic_stream, view):
        if field not in row:
            raise GenieTgnError(
                "'{f}' is not a column of '{v}' for traffic stream '{s}'; "
                'the columns are {c}'.format(f=field, v=view,
                                             s=traffic_stream,
                                             c=', '.join(sorted(row))))
        return row[field]

    @BaseConnection.locked
    def get_flow_statistics_data(self, traffic_stream, flow_data_field):
        '''Get the value of a 'Flow Statistics' column for a traffic stream

        Args:
            traffic_stream ('str'): OTG flow name
            flow_data_field ('str'): column name, such as 'Tx Frames'

        Returns:
            the column value

        Raises:
            GenieTgnError
        '''
        view = FLOW_STATISTICS
        row = self._statistics_row(traffic_stream, view)
        return self._statistics_field(row, flow_data_field, traffic_stream,
                                      view)

    @BaseConnection.locked
    def get_traffic_items_statistics_data(self, traffic_stream,
                                          traffic_data_field):
        '''Get the value of a 'Traffic Item Statistics' column for a stream

        OTG has one metric set per flow, so a traffic item and its flow are
        the same row.

        Args:
            traffic_stream ('str'): OTG flow name
            traffic_data_field ('str'): column name, such as 'Rx Frames'

        Returns:
            the column value

        Raises:
            GenieTgnError
        '''
        view = TRAFFIC_ITEM_STATISTICS
        row = self._statistics_row(traffic_stream, FLOW_STATISTICS)
        return self._statistics_field(row, traffic_data_field,
                                      traffic_stream, view)

    def _statistics_table(self, columns, export_to_filename=''):
        '''A PrettyTable of the flow metrics, one row per stream.'''
        stats = self.get_stats(view=FLOW_STATISTICS)
        available = sorted({key for row in stats.values() for key in row})
        columns = list(columns) if columns else (
            [TRAFFIC_ITEM] + available)
        unknown = [name for name in columns
                   if name != TRAFFIC_ITEM and name not in available]
        if unknown:
            raise GenieTgnError(
                'Unknown statistics column(s) {u}; the columns are '
                '{a}'.format(u=', '.join(unknown), a=', '.join(available)))

        table = PrettyTable()
        table.field_names = columns
        for name in sorted(stats):
            table.add_row([name if column == TRAFFIC_ITEM
                           else stats[name].get(column, '')
                           for column in columns])
        if export_to_filename:
            with open(export_to_filename, 'w') as export:
                export.write(table.get_csv_string())
            log.info('Statistics table exported to %s', export_to_filename)
        return table

    @BaseConnection.locked
    def create_flow_statistics_table(self, flow_stats_columns=None,
                                     csv_windows_path=None,
                                     csv_file_name=None, display=True,
                                     export_to_filename=''):
        '''Create a table of the 'Flow Statistics' view

        Args:
            flow_stats_columns ('list'): columns to include, all when
                                         omitted
            display ('bool'): log the table
            export_to_filename ('str'): also write it as CSV to this path

        Returns:
            'PrettyTable': the table, also kept for
            get_flow_statistics_table()

        Raises:
            GenieTgnError
        '''
        table = self._statistics_table(flow_stats_columns,
                                       export_to_filename)
        self._flow_statistics_table = table
        if display:
            log.info(banner(FLOW_STATISTICS))
            log.info(table)
        return table

    @BaseConnection.locked
    def get_flow_statistics_table(self):
        '''Returns the last Flow Statistics table created

        Raises:
            GenieTgnError: when create_flow_statistics_table() has not run
        '''
        if self._flow_statistics_table is None:
            raise GenieTgnError(
                'No Flow Statistics table has been created; call '
                'create_flow_statistics_table() first')
        return self._flow_statistics_table

    @BaseConnection.locked
    def get_traffic_item_statistics_table(self, traffic_stats_columns=None):
        '''Create a table of the 'Traffic Item Statistics' view

        Args:
            traffic_stats_columns ('list'): columns to include, all when
                                            omitted

        Returns:
            'PrettyTable'

        Raises:
            GenieTgnError
        '''
        table = self._statistics_table(traffic_stats_columns)
        log.info(banner(TRAFFIC_ITEM_STATISTICS))
        log.info(table)
        return table

    @BaseConnection.locked
    def get_traffic_items_from_genie_view(self, traffic_table):
        '''Returns the traffic item names of a traffic profile table

        Args:
            traffic_table ('PrettyTable'): a table from
                                           create_traffic_streams_table()

        Returns:
            'list': the traffic item names
        '''
        names = []
        for row in traffic_table.rows if hasattr(traffic_table, 'rows') \
                else []:
            # The profile table keeps the traffic item in its second column.
            if len(row) > 1 and str(row[1]).strip():
                names.append(str(row[1]).strip())
        return names

    @BaseConnection.locked
    def save_statistics_snapshot_csv(self, view_name,
                                     csv_windows_path=None,
                                     csv_file_name='Ixia_Statistics'):
        '''Save a statistics view as a CSV snapshot

        IxNetwork writes the snapshot on its own host; OTG returns the
        metrics, so the file is written locally, next to the other run
        artifacts by default.

        Args:
            view_name ('str'): a view from get_all_statistics_views()
            csv_windows_path ('str'): destination directory; default: the
                                      pyATS runinfo directory. A Windows
                                      path addresses the IxNetwork host and
                                      is ignored.
            csv_file_name ('str'): base name of the file; path separators
                                   are percent-encoded

        Returns:
            'str': the path of the written file

        Raises:
            GenieTgnError
        '''
        if view_name not in self._STATISTICS_VIEWS:
            raise GenieTgnError(
                "Unknown statistics view '{v}'; this traffic generator "
                'serves {a}'.format(v=view_name,
                                    a=', '.join(self._STATISTICS_VIEWS)))
        if csv_windows_path and _is_windows_path(csv_windows_path):
            # IxiaNative defaults this to 'C:\\Users\\'. Joining it here
            # would write a file with backslashes in its name.
            log.warning("Ignoring the Windows path '%s': the snapshot is "
                        'written on the host running the job, not on an '
                        'IxNetwork client', csv_windows_path)
            csv_windows_path = None
        directory = csv_windows_path or getattr(runtime, 'directory',
                                                None) or '.'
        path = _artifact_path(directory, '{f}.csv', f=csv_file_name)
        view = PORT_STATISTICS if view_name == PORT_STATISTICS \
            else FLOW_STATISTICS
        stats = self.get_stats(view=view)
        columns = sorted({key for row in stats.values() for key in row})
        table = PrettyTable()
        table.field_names = ['Name'] + columns
        for name in sorted(stats):
            table.add_row([name] + [stats[name].get(column, '')
                                    for column in columns])
        with open(path, 'w') as snapshot:
            snapshot.write(table.get_csv_string())
        log.info("Saved '%s' snapshot to %s", view_name, path)
        return path

    # -------------------------------------------------------------------------
    # Configuration, IxiaNative call signatures
    # -------------------------------------------------------------------------

    @BaseConnection.locked
    def save_configuration(self, config_file):
        '''Save the configuration of this traffic generator to a file

        IxNetwork writes a binary .ixncfg on its own host; OTG serialises
        the model, so this writes the configuration as JSON locally, in
        the form apply_configuration() and load_configuration() read back.

        Args:
            config_file ('str'): path to write

        Returns:
            'str': the path written

        Raises:
            GenieTgnError
        '''
        log.info(banner('Saving OTG configuration'))
        try:
            payload = self._configuration_text(self.get_config())
            with open(config_file, 'w') as handle:
                handle.write(payload)
        except Exception as err:
            raise GenieTgnError(
                "Unable to save the configuration of device '{d}' to "
                "'{f}': {e}".format(d=getattr(self.device, 'name', 'unknown'),
                                    f=config_file, e=err)) from err
        log.info("Saved the OTG configuration to '%s'", config_file)
        return config_file

    @BaseConnection.locked
    def regenerate_all_traffic_items(self):
        '''Regenerate all traffic items

        IxNetwork rebuilds each traffic item's packets after an edit. OTG
        has no separate generate step: pushing the configuration is what
        realises an edit, which is what this does.

        Returns:
            True

        Raises:
            GenieTgnError
        '''
        log.info(banner('Regenerating all OTG traffic streams'))
        return self.generate_traffic_streams()

    @BaseConnection.locked
    def get_traffic_attribute(self, attribute):
        '''Returns the specified attribute of the traffic configuration

        IxNetwork exposes a '/traffic' node with attributes such as
        'state'. The nearest OTG equivalents are served here; anything
        else has to be read from the configuration itself, through
        get_config().

        Args:
            attribute ('str'): 'state' or 'isTrafficRunning'

        Returns:
            the attribute value

        Raises:
            GenieTgnError
        '''
        running = any(state == 'started'
                      for state in self._flow_transmit_states().values())
        attributes = {'state': 'started' if running else 'stopped',
                      'isTrafficRunning': running}
        if attribute not in attributes:
            raise GenieTgnError(
                "Unable to check attribute '{a}'; this traffic generator "
                'serves {s}, and the rest of the configuration is available '
                'through get_config()'.format(
                    a=attribute, s=', '.join(sorted(attributes))))
        return attributes[attribute]

    @BaseConnection.locked
    def create_genie_statistics_view(self, view_create_interval=30,
                                     view_create_iteration=5,
                                     disable_tracking=False,
                                     disable_port_pair=False):
        '''Enable per-flow metrics, the OTG equivalent of the 'GENIE' view

        Ixia needs a custom statistics view to report per-stream loss; OTG
        reports it natively once flow metrics are enabled.
        '''
        self._require_api()
        log.info(banner('Enabling OTG flow metrics'))

        for flow in self._config.flows:
            if not flow.metrics.enable:
                flow.metrics.enable = True
                self._config_dirty = True
            if not flow.metrics.loss:
                flow.metrics.loss = True
                self._config_dirty = True

        self.translation_engine.commit()
        return True

    @BaseConnection.locked
    def get_current_packet_rate(self, first_sample=False):
        '''Return the current transmit rate of each traffic stream'''
        rates = self._sample_packet_rates()
        if first_sample:
            self._first_sample_packet_rate = dict(rates)
        for name, rate in rates.items():
            log.info("Traffic stream '%s' current rate: %s pps", name, rate)
        return rates

    @BaseConnection.locked
    def get_reference_packet_rate(self):
        '''Record and return the steady state transmit rate of each stream'''
        self._reference_packet_rate = self._sample_packet_rates()
        for name, rate in self._reference_packet_rate.items():
            log.info("Traffic stream '%s' reference rate: %s pps", name, rate)
        return self._reference_packet_rate

    def _sample_packet_rates(self):
        '''Reads the current per-flow transmit rate from OTG metrics.'''
        api = self._require_api()
        request = api.metrics_request()
        request.choice = request.FLOW
        return {metric.name: float(metric.frames_tx_rate or 0)
                for metric in api.get_metrics(request).flow_metrics}

    @BaseConnection.locked
    def create_traffic_streams_table(self, set_golden=False, clear_stats=False,
                                     clear_stats_time=30,
                                     view_create_interval=30,
                                     view_create_iteration=5,
                                     disable_tracking=False,
                                     disable_port_pair=False):
        '''Return a traffic profile of all configured streams as a table'''
        self._require_api()
        self.create_genie_statistics_view(
            view_create_interval=view_create_interval,
            view_create_iteration=view_create_iteration,
            disable_tracking=disable_tracking,
            disable_port_pair=disable_port_pair)

        if clear_stats:
            self.clear_statistics(wait_time=clear_stats_time)

        table = PrettyTable()
        table.field_names = PROFILE_HEADERS

        port_pairs = {}
        for flow in self._config.flows:
            tx_name, rx_name = self.translation_engine.flow_endpoints(flow)
            port_pairs[flow.name] = '{tx} - {rx}'.format(tx=tx_name, rx=rx_name)

        for name, row in sorted(self.get_stats(view=FLOW_STATISTICS).items()):
            table.add_row([
                port_pairs.get(name, ''),
                name,
                row[TX_FRAMES],
                row[RX_FRAMES],
                row[FRAMES_DELTA],
                row[TX_FRAME_RATE],
                row[RX_FRAME_RATE],
                row[LOSS_PERCENT],
                self._outage_seconds(name, row[FRAMES_DELTA]),
            ])

        log.info(banner('OTG traffic profile'))
        log.info('\n%s', table)

        if set_golden:
            log.info('Saving OTG traffic profile as the golden profile')
            self._golden_profile = table

        return table

    def _outage_seconds(self, flow_name, frames_delta):
        '''Converts a frame shortfall into an outage at the configured rate.'''
        expected_pps = self.translation_engine.get_flow_expected_pps(flow_name)
        if expected_pps <= 0 or frames_delta <= 0:
            return 0.0
        return round(frames_delta / expected_pps, 4)

    def get_golden_profile(self):
        '''Return the traffic profile saved as golden'''
        return self._golden_profile

    @BaseConnection.locked
    def compare_traffic_profile(self, profile1, profile2, loss_tolerance=5,
                                rate_tolerance=2):
        '''Compare two OTG traffic profiles'''
        log.info(banner('Comparing traffic profiles'))

        rows1 = self._profile_rows(profile1, 'profile1')
        rows2 = self._profile_rows(profile2, 'profile2')

        if set(rows1) != set(rows2):
            raise GenieTgnError(
                'Profiles do not have the same traffic items: {a} vs '
                '{b}'.format(a=sorted(rows1), b=sorted(rows2)))

        failed = False
        for name in sorted(rows1):
            log.info(banner("Comparing profiles for traffic item '{}'".format(name)))
            row1, row2 = rows1[name], rows2[name]

            for field, tolerance in ((TX_FRAME_RATE, rate_tolerance),
                                     (RX_FRAME_RATE, rate_tolerance),
                                     (LOSS_PERCENT, loss_tolerance)):
                difference = abs(_as_float(row1.get(field)) -
                                 _as_float(row2.get(field)))
                if difference > float(tolerance):
                    failed = True
                    log.error("* '%s' differs by %s between profiles, which "
                              "exceeds the tolerance of %s",
                              field, round(difference, 4), tolerance)
                else:
                    log.info("* '%s' difference between profiles is within the "
                             'tolerance of %s', field, tolerance)

        if failed:
            raise GenieTgnError('Comparison between traffic profiles failed')

        log.info('Comparison between traffic profiles passed')
        return True

    @staticmethod
    def _profile_rows(profile, label):
        '''Indexes a traffic profile table by traffic item name.'''
        if not isinstance(profile, PrettyTable) or not profile.field_names:
            raise GenieTgnError(
                '{} is not in expected format or missing data'.format(label))
        if TRAFFIC_ITEM not in profile.field_names:
            raise GenieTgnError(
                "{} does not contain a 'Traffic Item' column".format(label))

        index = profile.field_names.index(TRAFFIC_ITEM)
        return {row[index]: dict(zip(profile.field_names, row))
                for row in profile.rows}

    @staticmethod
    def _wait(wait_time, reason):
        if wait_time and float(wait_time) > 0:
            log.info("Waiting '%s' seconds %s", wait_time, reason)
            time.sleep(float(wait_time))


def _as_float(value):
    '''Coerces a profile cell to a float, treating blanks and '*' as zero.'''
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def _is_windows_path(path):
    '''Whether a path addresses a Windows filesystem.

    IxiaNative takes such paths because IxNetwork writes on its own host.
    '''
    return bool(re.match(r'^[A-Za-z]:[\\/]', str(path))) or '\\' in str(path)


# A controller returns a capture as a file, not as a count, so the frames
# have to be counted here. Both container formats appear in practice:
# snappi-ixnetwork rewrites a 'pcap' request to pcapng, while other
# controllers return classic pcap.
_PCAP_MAGICS = {b'\xd4\xc3\xb2\xa1': '<', b'\x4d\x3c\xb2\xa1': '<',
                b'\xa1\xb2\xc3\xd4': '>', b'\xa1\xb2\x3c\x4d': '>'}
_PCAPNG_SHB = b'\x0a\x0d\x0d\x0a'
_PCAPNG_PACKET_BLOCKS = (0x00000006, 0x00000003)


def _count_pcap_frames(data):
    '''Number of captured frames in a classic pcap or pcapng capture.'''
    if not data:
        return 0
    if data[:4] in _PCAP_MAGICS:
        return _count_classic_pcap_frames(data)
    if data[:4] == _PCAPNG_SHB:
        return _count_pcapng_frames(data)
    raise GenieTgnError(
        'Capture is neither pcap nor pcapng (first bytes {!r})'.format(
            bytes(data[:4])))


def _count_classic_pcap_frames(data):
    endian = _PCAP_MAGICS[data[:4]]
    count, offset = 0, 24
    while offset + 16 <= len(data):
        captured = struct.unpack_from(endian + 'I', data, offset + 8)[0]
        offset += 16 + captured
        count += 1
    return count


def _count_pcapng_frames(data):
    # Section headers carry the byte order of every block that follows.
    endian, count, offset = '<', 0, 0
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == _PCAPNG_SHB:
            endian = '>' if data[offset + 8:offset + 12] == \
                b'\x1a\x2b\x3c\x4d' else '<'
        block_type = struct.unpack_from(endian + 'I', data, offset)[0]
        length = struct.unpack_from(endian + 'I', data, offset + 4)[0]
        if length < 12:
            break
        if block_type in _PCAPNG_PACKET_BLOCKS:
            count += 1
        offset += length
    return count
