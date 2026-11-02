'''Shared IxNetwork controller helpers.

The OTG/Snappi plugin normally has no reason to import the Tcl client.  The
licensing API is an IxNetwork controller setting, however, and it must be
applied before ports are connected.  Keeping that narrow concern here lets
the native OTG and legacy IxiaNative connectors use the same behaviour
without coupling their traffic APIs.
'''

import logging
import re

from pyats.utils.secret_strings import SecretString, to_plaintext

from genie.harness.exceptions import GenieTgnError


log = logging.getLogger(__name__)


def normalize_ixia_license_servers(raw_servers):
    '''Return license servers as an ordered, de-duplicated list.

    A testbed may use a single server, a comma/semicolon-delimited string, or
    a list/tuple of either.  IxNet expects a list for ``-licensingServers``.
    '''
    if not raw_servers:
        return []

    if isinstance(raw_servers, str):
        candidates = re.split(r'[;,]', raw_servers)
    elif isinstance(raw_servers, (list, tuple)):
        candidates = []
        for item in raw_servers:
            if isinstance(item, str):
                candidates.extend(re.split(r'[;,]', item))
            elif item is not None:
                candidates.append(item)
    else:
        candidates = [raw_servers]

    servers = []
    for server in candidates:
        server = str(server).strip()
        if server and server not in servers:
            servers.append(server)
    return servers


def _credential_values(credentials):
    '''Return default credentials without leaking secret wrappers to IxNet.'''
    default = (credentials or {}).get('default', {})
    username = default.get('username')
    password = default.get('password')
    if isinstance(password, SecretString):
        password = to_plaintext(password)

    if username is None and password is None:
        return None, None
    if not username or password is None:
        raise GenieTgnError(
            'IxNetwork licensing requires both default username and password '
            'when either credential is configured.')
    return username, password


def _import_ixnet():
    '''Import the Tcl client only for connections that request licensing.'''
    try:
        from IxNetwork import IxNet
    except ImportError as err:
        raise GenieTgnError(
            "The 'IxNetwork' package is required to configure IxNetwork "
            'licensing from an OTG testbed.') from err
    return IxNet


def _licensing_object(ixnet):
    root = ixnet.getRoot()
    globals_obj = ixnet.getList(root, 'globals')[0]
    return ixnet.getList(globals_obj, 'licensing')[0]


def _read_servers(ixnet, licensing):
    return normalize_ixia_license_servers(
        ixnet.getAttribute(licensing, '-licensingServers'))


def _set_licensing_attributes(ixnet, licensing, settings):
    """Commit changed mode and tier values in request order."""
    for attribute, expected in settings:
        if expected is None:
            continue
        current = ixnet.getAttribute(licensing, attribute)
        if current != expected:
            ixnet.setAttribute(licensing, attribute, expected)
            ixnet.commit()


def _verify_licensing_settings(ixnet, licensing, license_servers, settings,
                              strict):
    """Read back requested values, rejecting mismatches in strict mode."""
    if license_servers:
        actual_servers = _read_servers(ixnet, licensing)
        if strict and actual_servers != license_servers:
            raise GenieTgnError(
                'IxNetwork did not retain the requested license servers.')

    for attribute, expected in settings:
        if expected is None:
            continue
        actual = ixnet.getAttribute(licensing, attribute)
        if strict and actual != expected:
            raise GenieTgnError(
                "IxNetwork did not retain requested licensing {}.".format(
                    attribute))


def apply_ixnetwork_license_settings(ixnet, license_servers=None,
                                     license_mode=None, license_tier=None,
                                     strict=False):
    '''Apply requested settings to an already-connected IxNet session.

    ``strict=False`` preserves IxiaNative's historic warning-only behaviour.
    The OTG bridge uses ``strict=True`` because proceeding to Snappi after a
    failed requested license update only hides the actionable error.
    '''
    try:
        licensing = _licensing_object(ixnet)
        if license_servers:
            ixnet.setAttribute(licensing, '-licensingServers', license_servers)
            ixnet.commit()

        settings = (('-mode', license_mode), ('-tier', license_tier))
        _set_licensing_attributes(ixnet, licensing, settings)
        _verify_licensing_settings(ixnet, licensing, license_servers,
                                   settings, strict)
        return True
    except Exception as err:
        if strict:
            if isinstance(err, GenieTgnError):
                raise
            raise GenieTgnError(
                'Failed to configure IxNetwork licensing: {}'.format(err)) from err
        log.warning('Failed to configure IxNetwork licensing: %s', err)
        return False


def _licensing_connect_args(ixnet, controller_host, tcl_port, version,
                            credentials, license_mode, license_tier):
    """Build Tcl connection arguments with optional authentication."""
    username, password = _credential_values(credentials)
    api_key = None
    if username is not None:
        try:
            api_key = ixnet.getApiKey(controller_host, '-username', username,
                                      '-password', password)
        except Exception as err:
            raise GenieTgnError(
                'Failed to obtain an IxNetwork API key for licensing.') from err

    connect_args = [
        controller_host,
        '-port', tcl_port,
        '-version', str(version),
        '-setAttribute', 'strict',
    ]
    if api_key:
        connect_args.extend(['-apiKey', api_key])
    if license_mode is not None:
        connect_args.extend(['-licenseMode', license_mode])
    if license_tier is not None:
        connect_args.extend(['-licenseTier', license_tier])
    return connect_args


def _disconnect_licensing_session(ixnet, primary_error):
    """Disconnect an established session while preserving its first failure."""
    try:
        result = ixnet.disconnect()
        if result != ixnet.OK:
            raise GenieTgnError(
                'IxNetwork rejected the temporary licensing disconnect.')
        log.info(
            'Temporary IxNetwork Tcl licensing session disconnected '
            'before native OTG/Snappi session creation.')
    except Exception as err:
        if primary_error is None:
            return err
        log.warning(
            'Failed to disconnect temporary IxNetwork licensing '
            'session after an earlier error.')
    return primary_error


def configure_ixnetwork_licensing(controller_host, tcl_port, version,
                                  license_servers=None, license_mode=None,
                                  license_tier=None, credentials=None):
    '''Configure IxNetwork licensing in a short-lived Tcl controller session.

    The caller must invoke this before creating a session that connects ports.
    It deliberately does not use ``-closeServerOnDisconnect``: the following
    native OTG/Snappi session must keep using the same API server.
    '''
    if license_servers is not None:
        license_servers = normalize_ixia_license_servers(license_servers)
        if not license_servers:
            raise GenieTgnError(
                'ixia_license_server_ip must contain at least one server.')

    # Controller endpoints, ports, credential values and individual license
    # server addresses are deliberately omitted from these lifecycle logs.
    # Mode and tier are controller configuration values, while the count still
    # proves that a server request was supplied without exposing its address.
    license_server_count = len(license_servers or ())
    log_fields = {
        'license_server_count': license_server_count,
        'license_mode': license_mode or '<unchanged>',
        'license_tier': license_tier or '<unchanged>',
    }

    ixnet = _import_ixnet()()
    connect_args = _licensing_connect_args(
        ixnet, controller_host, tcl_port, version, credentials,
        license_mode, license_tier)

    connected = False
    primary_error = None
    try:
        log.info(
            'Starting temporary IxNetwork Tcl licensing session '
            '(license_server_count=%(license_server_count)d, '
            'license_mode=%(license_mode)s, license_tier=%(license_tier)s).',
            log_fields)
        result = ixnet.connect(*connect_args)
        if result != ixnet.OK:
            raise GenieTgnError(
                'IxNetwork rejected the temporary licensing connection.')
        connected = True
        apply_ixnetwork_license_settings(
            ixnet, license_servers=license_servers,
            license_mode=license_mode, license_tier=license_tier, strict=True)
        log.info(
            'IxNetwork licensing strict read-back verified '
            '(license_server_count=%(license_server_count)d, '
            'license_mode=%(license_mode)s, license_tier=%(license_tier)s).',
            log_fields)
    except Exception as err:
        primary_error = err
    finally:
        if connected:
            primary_error = _disconnect_licensing_session(ixnet, primary_error)

    if primary_error is not None:
        if isinstance(primary_error, GenieTgnError):
            raise primary_error
        raise GenieTgnError(
            'Failed to configure IxNetwork licensing: {}'.format(
                primary_error)) from primary_error
    return True
