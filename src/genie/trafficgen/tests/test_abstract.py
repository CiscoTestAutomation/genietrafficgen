import os
import unittest
from pyats.topology import loader


class TestAbstractionImports(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.testbed = loader.load(
            os.path.join(os.path.dirname(__file__), 'testbed.yaml'))

    def test_ixianative(self):
        dev = self.testbed.devices.ixia1
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'IxiaNative')
        self.assertFalse(dev.default.connected)

        dev = self.testbed.devices.ixia2
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'IxiaNative')
        self.assertFalse(dev.default.connected)

    def test_ixiarestpy(self):
        dev = self.testbed.devices.ixia3
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'IxiaRestPy')
        self.assertFalse(dev.default.connected)

        dev = self.testbed.devices.ixia4
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'IxiaRestPy')
        self.assertFalse(dev.default.connected)

    def test_trex(self):

        dev = self.testbed.devices.trex2
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Trex')
        self.assertFalse(dev.default.connected)

        dev = self.testbed.devices.trex1
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Trex')
        self.assertFalse(dev.default.connected)

        dev = self.testbed.devices.trex3
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Trex')
        self.assertFalse(dev.default.connected)

    def test_pagent(self):
        dev = self.testbed.devices.pagent
        dev.instantiate()
        self.assertEqual(dev.default.__class__.__name__, 'Pagent')
        self.assertFalse(dev.default.connected)
