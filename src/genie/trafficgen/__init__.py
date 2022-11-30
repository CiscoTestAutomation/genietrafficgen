'''
    Module:
        genie.trafficgen

    Description:
        This is the sub-component of Genie for `genie.trafficgen`.

'''

# metadata
__version__ = '22.11'
__author__ = 'Cisco Systems Inc.'
__contact__ = ['asg-genie-support@cisco.com', 'pyats-support-ext@cisco.com']
__copyright__ = 'Copyright (c) 2022, Cisco Systems Inc.'


from genie import abstract
abstract.declare_package(__name__)

from .trafficgen import TrafficGen  # noqa
