#---------------------------------------------------------------------------
# *             This code will only work internally within Cisco
# *              Any attempt to use it externally will fail and 
# *                       no support will be provided
#---------------------------------------------------------------------------

try:
    from genie import abstract
    abstract.declare_token(platform='pagent')
except Exception as e:
    import warnings
    warnings.warn('Could not declare abstraction token: ' + str(e))

# import for abstraction
from .implementation import Pagent as TrafficGen  # noqa

# import for backward compatibility
from .implementation import Pagent  # noqa
