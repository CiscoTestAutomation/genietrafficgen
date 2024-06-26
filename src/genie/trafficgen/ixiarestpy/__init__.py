try:
    from genie import abstract
    abstract.declare_token(os='ixiarestpy')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

# import for abstraction
from .implementation import IxiaRestPy as TrafficGen  # noqa

# import for backward compatibility
from .implementation import IxiaRestPy  # noqa
