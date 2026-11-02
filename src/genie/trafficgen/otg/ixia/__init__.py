'''IXIA backend for the Open Traffic Generator (OTG) plugin.

Selected by ``platform: ixia`` on an ``os: otg`` device, which is the
migration target for a testbed on ``os: ixianative``.
'''

try:
    from genie import abstract
    abstract.declare_token(platform='ixia')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

# import for abstraction
from .implementation import IxiaOtg as TrafficGen  # noqa

# class definition for backward compatibility
from .implementation import IxiaOtg  # noqa
