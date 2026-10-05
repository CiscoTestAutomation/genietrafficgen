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

import json
import os
import re
import time
import logging

from prettytable import PrettyTable

# pyATS
from pyats.log.utils import banner
from pyats.connections import BaseConnection
from pyats.easypy import runtime

# Genie
from genie.trafficgen.trafficgen import TrafficGen
from genie.harness.exceptions import GenieTgnError

from genie.trafficgen.otg.mock import MockOtgApi
from genie.trafficgen.otg.translation import OtgTranslationEngine

log = logging.getLogger(__name__)

SUPPORTED_TRANSPORTS = ('mock', 'http', 'https', 'grpc')

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


# Kept identical to the ixianative traffic profile so that profiles captured by
# either plugin remain comparable and pickle/unpickle interchangeably.
PROFILE_HEADERS = ['Source/Dest Port Pair', 'Traffic Item', 'Tx Frames',
                   'Rx Frames', 'Frames Delta', 'Tx Frame Rate',
                   'Rx Frame Rate', 'Loss %', 'Outage (seconds)']


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
            "'https' and 'grpc'. Install it with "
            "'pip install genie.trafficgen[otg]', or use transport='mock' "
            'for hardware-free simulation.') from err
    return snappi


class Otg(TrafficGen):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.device = self.device or kwargs.get('device')
        self.via = kwargs.get('via', 'tgn')

        connection_info = self.connection_info

        self.transport = str(connection_info.get('transport', 'mock')).lower()
        self.location = connection_info.get('location')

        if self.transport not in SUPPORTED_TRANSPORTS:
            raise GenieTgnError(
                "Unsupported transport '{t}' for device '{d}'. Expected one "
                'of: {s}'.format(t=self.transport,
                                 d=getattr(self.device, 'name', 'unknown'),
                                 s=', '.join(SUPPORTED_TRANSPORTS)))

        # 'location: mock' is shorthand for the in-memory simulator.
        if self.location == 'mock':
            self.transport = 'mock'

        if not self.location:
            if self.transport == 'grpc':
                self.location = '{ip}:{port}'.format(
                    ip=connection_info.get('ip', '127.0.0.1'),
                    port=connection_info.get('port', 40051))
            else:
                self.location = '{protocol}://{ip}:{port}'.format(
                    protocol=connection_info.get('protocol', 'https'),
                    ip=connection_info.get('ip', '127.0.0.1'),
                    port=connection_info.get('port', 8443))

        # Verify TLS certificates by default. Labs that terminate on a
        # self-signed controller certificate must opt out explicitly with
        # 'verify_certificate: False' rather than shipping an insecure default.
        self.verify_certificate = connection_info.get(
            'verify_certificate', True)
        self.timeout = connection_info.get('timeout', 30)

        # snappi extension driving a vendor backend, e.g. 'ixnetwork' or 'trex'.
        self.ext = connection_info.get('ext')

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

        self.translation_engine = OtgTranslationEngine(self)

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

        if self.transport == 'mock':
            self._api = MockOtgApi(location=self.location, transport='mock',
                                   timeout=self.timeout)
        else:
            self._api = self._create_snappi_api()
            self._quieten_absent_counters()

        self._config = self._api.config()
        self._traffic_streams = []
        self._flow_baselines = {}
        self._port_baselines = {}
        self._config_dirty = False
        self._controller_has_flows = False

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

    def _create_snappi_api(self):
        '''Builds a real snappi client for the http/https/grpc transports.'''
        snappi = import_snappi()
        kwargs = {'location': self.location, 'verify': self.verify_certificate}

        # snappi rejects ext and transport together: an extension owns its own
        # transport to the vendor backend.
        if self.ext:
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
            payload = json.dumps(config) if isinstance(config, dict) else config
            deserialized = api.config()
            deserialized.deserialize(payload)
            config = deserialized

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

    def set_state(self, state):
        '''Push an OTG control state (traffic, protocol or port)'''
        return self._require_api().set_control_state(state)

    def get_metrics(self, request):
        '''Retrieve typed OTG metrics for a metrics request'''
        return self._require_api().get_metrics(request)

    def get_states(self, request):
        '''Retrieve OTG protocol or link operational states'''
        api = self._require_api()
        if not hasattr(api, 'get_states'):
            raise GenieTgnError(
                'get_states() requires the snappi SDK and an OTG controller '
                "that supports it; it is not available with transport='mock'.")
        return api.get_states(request)

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
        return self.translation_engine.check_traffic_loss(*args, **kwargs)

    def get_stats(self, *args, **kwargs):
        '''Return port or flow statistics as a dictionary'''
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

        name = '{d}_{f}'.format(d=self.device.name,
                                f=os.path.basename(source))
        destination = os.path.join(runtime.directory, name)

        try:
            with open(destination, 'w') as archived:
                archived.write(content)
        except OSError as err:
            # Archiving is a side effect of loading, so it must never be the
            # reason a run fails.
            log.warning("Unable to archive OTG configuration to '%s': %s",
                        destination, err)
            return None

        log.info("Archived OTG configuration as '%s'", destination)
        return destination

    @BaseConnection.locked
    def load_configuration(self, configuration, wait_time=60):
        '''Load an OTG configuration file (JSON or YAML) onto the controller'''
        log.info(banner("Loading OTG configuration '{}'".format(configuration)))
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
        return self.translation_engine.send_arp(wait_time=wait_time)

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

        for name, row in sorted(self.get_stats(view='Flow Statistics').items()):
            table.add_row([
                port_pairs.get(name, ''),
                name,
                row['Tx Frames'],
                row['Rx Frames'],
                row['Frames Delta'],
                row['Tx Frame Rate'],
                row['Rx Frame Rate'],
                row['Loss %'],
                self._outage_seconds(name, row['Frames Delta']),
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

            for field, tolerance in (('Tx Frame Rate', rate_tolerance),
                                     ('Rx Frame Rate', rate_tolerance),
                                     ('Loss %', loss_tolerance)):
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
        if 'Traffic Item' not in profile.field_names:
            raise GenieTgnError(
                "{} does not contain a 'Traffic Item' column".format(label))

        index = profile.field_names.index('Traffic Item')
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
