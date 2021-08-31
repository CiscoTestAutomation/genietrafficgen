import os
import unittest

from pyats.topology import loader

import unicon
from unicon.plugins.tests.mock.mock_device_iosxe import MockDeviceTcpWrapperIOSXE

unicon.settings.Settings.POST_DISCONNECT_WAIT_SEC = 0
unicon.settings.Settings.GRACEFUL_DISCONNECT_WAIT_SEC = 0.2


class TestPagent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.md = MockDeviceTcpWrapperIOSXE(port=0, state='general_enable')
        cls.md.start()
        telnet_port = cls.md.ports[0]

        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        tb.devices.pagent.connections.tgn['ip'] = '127.0.0.1'
        tb.devices.pagent.connections.tgn['port'] = telnet_port
        cls.dev = tb.devices.pagent

    def test_connect(self):
        dev = self.dev
        try:
            dev.connect()
            self.assertIsInstance(
                dev.cli.execute,
                unicon.plugins.generic.service_implementation.Execute)
            self.assertIsInstance(
                dev.cli.configure,
                unicon.plugins.generic.service_implementation.Configure)
            output = dev.execute('show version')
            self.assertIn('IOS-XE', output)
        finally:
            dev.disconnect()

    def test_connect_connect(self):
        dev = self.dev

        try:
            dev.connect()
            dev.connect()
            dev.disconnect()
            dev.connect()
        finally:
            dev.disconnect()

    @classmethod
    def tearDownClass(cls):
        cls.md.stop()
