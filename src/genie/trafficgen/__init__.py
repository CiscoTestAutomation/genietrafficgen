'''
    Module:
        genie.trafficgen

    Description:
        This is the sub-component of Genie for `genie.trafficgen`.

'''

# metadata
__version__ = '19.10'
__author__ = 'Cisco Systems Inc.'
__contact__ = ['asg-genie-support@cisco.com', 'pyats-support-ext@cisco.com']
__copyright__ = 'Copyright (c) 2019, Cisco Systems Inc.'


from genie import abstract
abstract.declare_package(__name__)


# try to record usage statistics
#  - only internal cisco users will have stats.CesMonitor module
#  - below code does nothing for DevNet users -  we DO NOT track usage stats
#    for PyPI/public/customer users
try:
    # new internal cisco-only pkg since devnet release
    from ats.cisco.stats import CesMonitor
except Exception:
    try:
        # legacy pyats version, stats was inside utils module
        from ats.utils.stats import CesMonitor
    except Exception:
        CesMonitor = None

finally:
    if CesMonitor is not None:
        # CesMonitor exists -> this is an internal cisco user
        CesMonitor(action = __name__, application='Genie').post()
        CesMonitor(action = __name__, application='pyATS Packages').post()
