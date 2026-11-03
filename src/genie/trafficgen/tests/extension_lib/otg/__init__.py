from genie import abstract
abstract.declare_token(os='otg')

# Re-exported for the same reason as the root: an 'os: otg' device with no
# platform of ours must still resolve to the public implementation.
from genie.trafficgen.otg.implementation import Otg as TrafficGen  # noqa
