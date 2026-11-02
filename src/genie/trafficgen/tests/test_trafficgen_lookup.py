'''Tests for the traffic generator lookup and its entry point extensions.

Every test here fixes the set of discovered packages with a patch, so the
result does not depend on which extension packages happen to be installed
alongside genie.trafficgen in the environment running the tests.
'''

import logging
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pyats.topology import loader

from genie.harness.exceptions import GenieTgnError
from genie import trafficgen as trafficgen_package
from genie.trafficgen import trafficgen as lookup
from genie.trafficgen.tests import extension_lib

TESTBED = os.path.join(os.path.dirname(__file__), 'testbed.yaml')


def entry_point(name='example', value='genie.trafficgen.tests.extension_lib',
                load=None):
    '''An entry point of the kind importlib.metadata hands out.'''
    return SimpleNamespace(
        name=name, value=value,
        load=load if load is not None else lambda: extension_lib)


class LookupTestCase(unittest.TestCase):
    '''Runs each test against a known set of discovered packages.'''

    entries = ()

    def setUp(self):
        self.testbed = loader.load(TESTBED)
        patcher = patch.object(lookup, 'get_entry_points',
                               return_value=list(self.entries))
        self.get_entry_points = patcher.start()
        self.addCleanup(patcher.stop)
        lookup.get_trafficgen_packages.cache_clear()
        self.addCleanup(lookup.get_trafficgen_packages.cache_clear)

    def instantiate(self, device_name, platform=None):
        # Instantiated, not connected: each test loads its own testbed, so
        # there is no session to tear down afterwards.
        device = self.testbed.devices[device_name]
        if platform is not None:
            device.platform = platform
        return device.instantiate(via='tgn', alias='tgn')


class TestWithoutExtensions(LookupTestCase):
    '''With nothing registered, the lookup is this package alone.'''

    def test_only_this_package_is_discovered(self):
        self.assertEqual(lookup.get_trafficgen_packages(),
                         (trafficgen_package,))

    def test_os_token_still_resolves(self):
        self.assertEqual(type(self.instantiate('otg2')).__name__, 'Otg')

    def test_ixianative_still_resolves(self):
        self.assertEqual(type(self.instantiate('ixia2')).__name__,
                         'IxiaNative')


class TestWithAnExtension(LookupTestCase):
    '''A registered package adds its tokens to the same lookup.'''

    entries = (entry_point(),)

    def test_the_extension_is_discovered(self):
        self.assertEqual(
            [package.__name__ for package in lookup.get_trafficgen_packages()],
            ['genie.trafficgen', extension_lib.__name__])

    def test_its_platform_resolves_to_its_class(self):
        connection = self.instantiate('otg2', platform='example')
        self.assertEqual(type(connection).__name__, 'ExampleOtg')
        self.assertEqual(connection.platform, 'example')

    def test_a_platform_it_does_not_declare_resolves_to_this_package(self):
        self.assertEqual(type(self.instantiate('otg2')).__name__, 'Otg')

    def test_another_os_is_left_alone(self):
        self.assertEqual(type(self.instantiate('ixia2')).__name__,
                         'IxiaNative')

    def test_an_extension_class_can_be_named_in_the_testbed(self):
        device = self.testbed.devices.otg1
        device.platform = 'example'
        device.connections.tgn['class'] = (
            'genie.trafficgen.tests.extension_lib.otg.example.ExampleOtg')
        connection = device.instantiate(via='tgn', alias='tgn')
        self.assertEqual(type(connection).__name__, 'ExampleOtg')

    def test_a_class_named_in_the_testbed_is_not_redirected(self):
        # 'class' names genie.trafficgen.otg.Otg, so the lookup is bypassed
        # and the extension cannot step in: the named class has to serve the
        # platform itself.
        device = self.testbed.devices.otg1
        device.platform = 'example'
        with self.assertRaises(GenieTgnError) as ctx:
            device.instantiate(via='tgn', alias='tgn')
        self.assertIn("Unsupported OTG platform 'example'", str(ctx.exception))


class TestBrokenExtensions(LookupTestCase):
    '''A package that cannot be used is skipped, with a warning naming it.'''

    def assert_skipped(self, entry, *expected):
        with self.assertLogs(lookup.log, level=logging.WARNING) as logs:
            self.assertEqual(lookup.get_trafficgen_packages(),
                             (trafficgen_package,))
        message = '\n'.join(logs.output)
        self.assertIn(entry.name, message)
        for text in expected:
            self.assertIn(text, message)

    def _patch(self, entry):
        self.get_entry_points.return_value = [entry]
        lookup.get_trafficgen_packages.cache_clear()
        return entry

    def test_a_package_that_cannot_be_imported(self):
        def load():
            raise ImportError('no module named unobtainable')

        entry = self._patch(entry_point(name='unobtainable', load=load))
        self.assert_skipped(entry, 'no module named unobtainable')

    def test_a_package_that_is_not_an_abstraction_package(self):
        entry = self._patch(entry_point(name='not-abstract',
                                        load=lambda: SimpleNamespace()))
        self.assert_skipped(entry, '__abstract_pkg')

    def test_a_package_with_a_different_abstraction_order(self):
        other = SimpleNamespace(
            __name__='other',
            _SimpleNamespace__unused=None)
        setattr(other, '__abstract_pkg',
                SimpleNamespace(name='other', order=['os'], feature=None,
                                learn=lambda: None))
        entry = self._patch(entry_point(name='misordered', load=lambda: other))
        self.assert_skipped(entry, 'abstraction order')

    def test_a_package_declaring_a_different_feature(self):
        order = list(getattr(trafficgen_package, '__abstract_pkg').order)
        other = SimpleNamespace(__name__='other')
        setattr(other, '__abstract_pkg',
                SimpleNamespace(name='other', order=order, feature='clean',
                                learn=lambda: None))
        entry = self._patch(entry_point(name='misfeatured', load=lambda: other))
        self.assert_skipped(entry, 'abstraction feature')

    def test_a_package_that_fails_to_learn(self):
        order = list(getattr(trafficgen_package, '__abstract_pkg').order)

        def learn():
            raise ImportError("no module named 'a_backend_sdk'")

        other = SimpleNamespace(__name__='other')
        setattr(other, '__abstract_pkg',
                SimpleNamespace(name='other', order=order, feature=None,
                                learn=learn))
        entry = self._patch(entry_point(name='unlearnable', load=lambda: other))
        self.assert_skipped(entry, 'a_backend_sdk')

    def test_a_broken_package_leaves_the_lookup_working(self):
        def load():
            raise ImportError('nope')

        self._patch(entry_point(name='unobtainable', load=load))
        with self.assertLogs(lookup.log, level=logging.WARNING):
            self.assertEqual(type(self.instantiate('otg2')).__name__, 'Otg')


class TestDiscoveryIsCached(LookupTestCase):
    '''Entry points are rescanned once per process, not once per device.'''

    entries = (entry_point(),)

    def test_repeated_lookups_scan_once(self):
        for _ in range(3):
            lookup.get_trafficgen_packages()
        self.assertEqual(self.get_entry_points.call_count, 1)


class TestLookupWithoutSnappi(unittest.TestCase):
    '''The lookup imports every traffic generator package it can find.'''

    def test_resolving_a_device_does_not_need_snappi(self):
        # The first lookup imports every vendor package and caches the result
        # per process, so check it in a fresh interpreter.
        result = subprocess.run(
            [sys.executable, '-c',
             "import sys; sys.modules['snappi'] = None; "
             'from pyats.topology import loader; '
             'dev = loader.load(sys.argv[1]).devices.otg2; '
             "print(type(dev.instantiate(via='tgn')).__name__)",
             TESTBED],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Otg', result.stdout)


if __name__ == '__main__':
    unittest.main()
