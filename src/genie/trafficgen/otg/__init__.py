try:
    from genie import abstract
    abstract.declare_token(os='otg')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

# import for abstraction
from .implementation import Otg as TrafficGen  # noqa

# class definition for backward compatibility
from .implementation import Otg  # noqa

# alias used by the original genie.trafficgen.otg prototype testbeds
from .implementation import Otg as OtgTrafficGen  # noqa
