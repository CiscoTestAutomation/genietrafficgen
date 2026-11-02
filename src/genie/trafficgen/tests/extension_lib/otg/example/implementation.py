'''An OTG backend added by an extension package, for testing the lookup.'''

from genie.trafficgen.otg.implementation import Otg


class ExampleOtg(Otg):
    '''Adds a platform of its own to the OTG plugin.'''

    SUPPORTED_PLATFORMS = ('example',)
    SUPPORTED_TRANSPORTS = ('mock',)
    DEFAULT_TRANSPORT = 'mock'
    USES_TEST_PORTS = False
