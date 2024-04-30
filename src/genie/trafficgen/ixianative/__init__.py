try:
    from genie import abstract
    abstract.declare_token(os='ixianative')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

# import for abstraction
from .implementation import IxiaNative as TrafficGen  # noqa

# impprt for backward compatibility
from .implementation import IxiaNative  # noqa
