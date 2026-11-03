'''A traffic generator extension package, for testing the plugin lookup.

Stands in for a package registered under the ``genie.trafficgen`` entry
point. It mirrors what such a package has to do: declare the same abstraction
order and feature as ``genie.trafficgen``, re-export the classes of the nodes
it supersedes, and add its own tokens below them.
'''

from genie import abstract
abstract.declare_package()

# The merged tree supersedes this package's shared nodes with this one, so the
# root has to answer the lookups the root of genie.trafficgen answers.
from genie.trafficgen.trafficgen import TrafficGen  # noqa
