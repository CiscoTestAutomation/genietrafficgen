'''What an IxNetwork script asks for that OTG has no way to answer.

The IxiaNative plugin exposes the IxNetwork object model: callers hold
vports, traffic items, flow groups and QuickTest objects, and read their
attributes. OTG models a traffic generator by configuration and metrics
instead, and has no objects to hand back.

Every such method is still defined on the IXIA OTG plugin, so a script
that calls one is told which IxNetwork construct it is reaching for and
what to use instead, rather than failing with an AttributeError several
frames away from the cause.
'''

from genie.harness.exceptions import GenieTgnError

CONFIGURATION = ('the OTG configuration describes this, so read it with '
                 'get_config() or set it with apply_configuration()')
STATISTICS = ('read the metrics with get_stats() or '
              'get_flow_statistics_data() instead')
QUICK_FLOW_GROUPS = ('Quick Flow Groups are an IxNetwork feature with no OTG '
                     'equivalent')
QUICKTEST = 'QuickTest is an IxNetwork feature with no OTG equivalent'

# Method name -> why OTG cannot serve it, and what to use instead.
UNSUPPORTED = {
    # The IxNetwork object model. These return restpy objects, which exist
    # only on an IxNetwork session.
    'find_traffic_stream_object':
        'a traffic item is an IxNetwork object; OTG addresses a stream by '
        'name, so pass the name to the method that needs it',
    'get_traffic_stream_objects':
        'traffic items are IxNetwork objects; '
        'get_traffic_stream_names() returns the OTG stream names',
    'get_traffic_stream_attribute':
        'traffic item attributes are IxNetwork fields; ' + CONFIGURATION,
    'find_flow_group_object':
        'a flow group is an IxNetwork subdivision of a traffic item, which '
        'OTG does not have; a stream is its own group, see '
        'get_flow_group_names()',
    'get_flow_group_objects':
        'flow groups are IxNetwork objects; get_flow_group_names() returns '
        'the OTG names',
    'get_flow_group_attribute':
        'flow group attributes are IxNetwork fields; ' + CONFIGURATION,
    'find_flow_statistics_page_obj':
        'statistics pages belong to the IxNetwork view model; ' + STATISTICS,
    'find_traffic_item_statistics_page_obj':
        'statistics pages belong to the IxNetwork view model; ' + STATISTICS,

    # Quick Flow Groups are an IxNetwork feature for unconfigured streams.
    'get_quick_flow_group_names':
        'Quick Flow Groups are an IxNetwork feature; OTG has only the '
        'flows of the configuration, see get_traffic_stream_names()',
    'get_quick_flow_group_objects': QUICK_FLOW_GROUPS,
    'find_quick_flow_group_object': QUICK_FLOW_GROUPS,
    'get_quick_flow_group_attribute': QUICK_FLOW_GROUPS,
    'start_quick_flow_group':
        'Quick Flow Groups are an IxNetwork feature; configure the stream '
        'and start it with start_traffic_stream()',
    'stop_quick_flow_group':
        'Quick Flow Groups are an IxNetwork feature; stop the stream with '
        'stop_traffic_stream()',

    # QuickTest is IxNetwork's packaged RFC test suite.
    'find_quicktest_object': QUICKTEST,
    'load_quicktest_configuration': QUICKTEST,
    'execute_quicktest':
        QUICKTEST + '; drive the RFC procedure from the script, over the '
        'OTG flows',
    'get_quicktest_results_attribute': QUICKTEST,
    'generate_export_quicktest_report': QUICKTEST,

    # Chassis, vports and layer 1. OTG ports come from the configuration
    # and their locations name the chassis.
    'add_chassis':
        'OTG reaches a chassis through the port locations of the '
        'configuration, so there is no separate chassis to add',
    'get_vports':
        'vports are IxNetwork objects; the OTG ports are in the '
        'configuration, and their counters in '
        'get_stats("Port Statistics")',
    'get_ixia_virtual_port':
        'vports are IxNetwork objects; OTG addresses a port by its '
        'configured name',
    'get_ixia_virtual_port_attribute':
        'vport attributes are IxNetwork fields; ' + CONFIGURATION,
    'get_ixia_virtual_port_capture':
        'the capture object belongs to an IxNetwork vport; use '
        'enable_data_packet_capture() and save_packet_capture_file()',
    'set_ixia_virtual_ports':
        'OTG takes its ports from the configuration, so there is no '
        'separate port assignment step',
    'enable_vlan_on_interface':
        'a VLAN belongs to the emulated device or the flow packet headers '
        'in OTG; ' + CONFIGURATION,
    'change_l1config_media':
        'OTG sets media through the layer1 section of the configuration; '
        + CONFIGURATION,
    'configure_autonegotiate':
        'OTG sets auto-negotiation through the layer1 section of the '
        'configuration; ' + CONFIGURATION,

    # Traffic item construction and tracking.
    'create_l2_traffic_stream':
        'OTG builds a stream from the configuration; use '
        'apply_configuration(), or configure_ipv4_data_traffic() for the '
        'compatibility path',
    'create_l3_traffic_stream':
        'OTG builds a stream from the configuration; use '
        'apply_configuration(), or configure_ipv4_data_traffic() for the '
        'compatibility path',
    'enable_flow_tracking_filter':
        'tracking filters belong to the IxNetwork view model; OTG reports '
        'per-flow metrics natively, see create_genie_statistics_view()',
}


def _unsupported_method(name, reason):
    '''Build the method that reports `reason` for `name`.'''

    def method(self, *args, **kwargs):
        raise GenieTgnError(
            "{n}() is not available on an OTG traffic generator: "
            '{r}.'.format(n=name, r=reason))

    method.__name__ = name
    method.__doc__ = 'Not available on OTG: {}.'.format(reason)
    return method


def install_unsupported(cls, base, table=UNSUPPORTED):
    '''Define the unsupported IxiaNative methods on `cls`.

    A name already implemented by `base` is left alone, so implementing
    one of these on the OTG plugin later is all it takes to retire its
    entry here.
    '''
    for name, reason in sorted(table.items()):
        if hasattr(base, name):
            continue
        method = _unsupported_method(name, reason)
        method.__qualname__ = '{c}.{n}'.format(c=cls.__name__, n=name)
        setattr(cls, name, method)
    return cls
