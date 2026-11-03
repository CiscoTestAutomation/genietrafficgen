from genie import abstract
abstract.declare_token(platform='example')

from .implementation import ExampleOtg  # noqa
from .implementation import ExampleOtg as TrafficGen  # noqa
