'''

Todo add docstrings 
how to run UT 
Mock links to explain how to use

cd 
python -m unittest test_ixiangpf.py -v

# TCL is not built for MacOS so skip pipeline tests for macbook/darwin platform

'''

import os, sys
from prettytable import PrettyTable
from pyats.topology import loader
import unittest
from unittest.mock import Mock, MagicMock, patch, call 
from genie.harness.exceptions import GenieTgnError
try:
    from ixiatcl import IxiaTcl
    failed_import = False
except ModuleNotFoundError:
    failed_import = True

class TestIxiaNgpf(unittest.TestCase):

    # TCL is not built for MacOS so skip pipeline tests for macbook/darwin platform
    @unittest.skipIf(sys.platform == "darwin", "Skip test only for mac OS")
    @unittest.skipIf(failed_import, "Necessary module not imported")
    def test_connect_success(self):
        ''' '''

        # New method
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia8
        dev.instantiate()
        dev.default.ixiangpf = Mock()
        dev.default.ixiahlt = Mock()

        ixngpf_mock = dev.default.ixiangpf
        ixiahlt_mock = dev.default.ixiahlt
        ixiahlt_mock.SUCCESS = '1'

        ixngpf_mock.connect = Mock(return_value={"status": '1'})
        # execute function 
        dev.connect()

        # check mock
        ixngpf_mock.connect.assert_called()
        ixngpf_mock.connect.assert_called_with(ixnetwork_tcl_server=str(dev.connections.tgn.ixnetwork_api_server_ip)+':'+str(dev.connections.tgn.ixnetwork_tcl_port), \
                                    tcl_server=dev.connections.tgn.ixia_chassis_ip, device=dev.connections.tgn.ixia_chassis_ip, \
                                    port_list=dev.connections.tgn.ixia_port_list, break_locks=1, connect_timeout=30)

    @unittest.skipIf(sys.platform == "darwin", "Skip test only for mac OS")
    @unittest.skipIf(failed_import, "Necessary module not imported")
    def test_connect_failure(self):
        ''' '''
        
        # New method
        tb_file = os.path.join(os.path.dirname(__file__), 'testbed.yaml')
        tb = loader.load(tb_file)
        dev = tb.devices.ixia8
        dev.instantiate()
        dev.default.ixiangpf = Mock()
        dev.default.ixiahlt = Mock()

        ixngpf_mock = dev.default.ixiangpf
        ixiahlt_mock = dev.default.ixiahlt
        ixiahlt_mock.SUCCESS = '1'

        ixngpf_mock.connect = Mock(return_value={"status": '0'})
        with self.assertRaisesRegex(GenieTgnError, "TGN-ERROR: Failed to connect to device '{n}' on port '{p}'".format(n=dev.name, p=dev.ixnetwork_tcl_port)):
            dev.connect()
