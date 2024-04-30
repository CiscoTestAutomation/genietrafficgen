try:
    from genie import abstract
    abstract.declare_token(os='trex')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

# import for abstraction
from .implementation import Trex as TrafficGen  # noqa

# class definition for backward compatibility
from .implementation import Trex  # noqa
