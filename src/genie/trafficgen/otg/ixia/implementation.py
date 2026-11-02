'''
IXIA OTG plugin.

The public OTG plugin plus the IxNetwork-only method names of IxiaNative,
so a script written for ``os: ixianative`` finds every method it calls.
It connects exactly as the public plugin does: IxNetwork is reached with
``ext: ixnetwork``, and a controller that speaks OTG natively without it.

Selected with ``platform: ixia`` on an ``os: otg`` device.
'''

# Genie
from genie.trafficgen.otg.implementation import Otg
from genie.trafficgen.otg.ixia.compat import install_unsupported


class IxiaOtg(Otg):
    '''OTG plugin answering to every IxiaNative method name.

    Everything a traffic generator does is inherited from :class:`Otg`,
    including the IxiaNative call signatures for capture, rate and frame
    size, per-stream control and statistics. What this adds is the
    IxNetwork-only method names, which report what to use instead (see
    :mod:`~genie.trafficgen.otg.ixia.compat`).

    No connection default changes: a device that already sets
    ``platform: ixia`` connects as it did before this class existed.
    '''

    SUPPORTED_PLATFORMS = ('ixia',)
    DEFAULT_PLATFORM = 'ixia'


install_unsupported(IxiaOtg, Otg)
