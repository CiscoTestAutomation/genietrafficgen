################################################################################
#                        genie.trafficgen Makefile
#
# Author:
#   pyats-support-ext@cisco.com
#
# Support:
#   pyats-support-ext@cisco.com
#
# Version:
#   v3.0
#
# Date:
#   February 2019
#
# About This File:
#   This script will build the genie.trafficgen package for distribution in
#   PyPI server
#
# Requirements:
#	1. Module name is the same as package name.
#	2. setup.py file is stored within the module folder
################################################################################

# Variables
PKG_NAME      = genietrafficgen
BUILD_DIR     = $(shell pwd)/__build__
DIST_DIR      = $(BUILD_DIR)/dist
PROD_USER     = pyadm@pyats-ci
PROD_PKGS     = /auto/pyats/packages/cisco-shared/genietrafficgen
PYTHON        = python
TESTCMD       = $(PYTHON) setup.py test
BUILD_CMD     = $(PYTHON) setup.py bdist_wheel --dist-dir=$(DIST_DIR)
PYPIREPO      = pypitest

# Development pkg requirements
DEPENDENCIES  = restview psutil Sphinx wheel asynctest
DEPENDENCIES += setproctitle  sphinx-rtd-theme 
DEPENDENCIES += pip-tools Cython requests

ifeq ($(MAKECMDGOALS), devnet)
	BUILD_CMD += --devnet
endif

.PHONY: clean package distribute develop undevelop help devnet\
        docs test install_build_deps uninstall_build_deps

help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo ""
	@echo "package               Build the package"
	@echo "test                  Test the package"
	@echo "distribute            Distribute the package to internal Cisco PyPi server"
	@echo "clean                 Remove build artifacts"
	@echo "develop               Build and install development package"
	@echo "undevelop             Uninstall development package"
	@echo "docs                  Build Sphinx documentation for this package"
	@echo "devnet                Build DevNet package."
	@echo "install_build_deps    install pyats-distutils"
	@echo "uninstall_build_deps  remove pyats-distutils"
	@echo ""
	@echo "     --- build arguments ---"
	@echo " DEVNET=true              build for devnet style (cythonized, no ut)"

devnet: package
	@echo "Completed building DevNet packages"
	@echo ""

install_build_deps:
	@echo "no action"

uninstall_build_deps:
	@echo "no action"

docs:
	@echo ""
	@echo "--------------------------------------------------------------------"
	@echo "Building $(PKG_NAME) documentation for preview: $@"
	@sphinx-build -b html -c docs/ -d ./__build__/documentation/doctrees docs/ ./__build__/documentation/html
	@echo "Completed building docs for preview."
	@echo ""


test:
	@$(TESTCMD)

package:
	@echo ""
	@echo "--------------------------------------------------------------------"
	@echo "Building $(PKG_NAME) distributable: $@"
	@echo ""
	
	$(BUILD_CMD)
	
	@echo ""
	@echo "Completed building: $@"
	@echo ""

develop:
	@echo ""
	@echo "--------------------------------------------------------------------"
	@echo "Building and installing $(PKG_NAME) development distributable: $@"
	@echo ""
	
	@pip install $(DEPENDENCIES)
	
	@$(PYTHON) setup.py develop --no-deps
		
	@echo ""
	@echo "Completed building and installing: $@"
	@echo ""

undevelop:
	@echo ""
	@echo "--------------------------------------------------------------------"
	@echo "Uninstalling $(PKG_NAME) development distributable: $@"
	@echo ""
	
	@$(PYTHON) setup.py develop --no-deps -q --uninstall
	
	@echo ""
	@echo "Completed uninstalling: $@"
	@echo ""

clean:
	@echo ""
	@echo "--------------------------------------------------------------------"
	@echo "Removing make directory: $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo ""
	@echo "Removing build artifacts ..."
	@$(PYTHON) setup.py clean
	@echo ""
	@echo "Done."
	@echo ""

distribute:
	@echo ""
	@echo "--------------------------------------------------------------------"
	@echo "Copying all distributable to $(PROD_PKGS)"
	@test -d $(DIST_DIR) || { echo "Nothing to distribute! Exiting..."; exit 1; }
	@ssh -q $(PROD_USER) 'test -e $(PROD_PKGS)/$(PKG_NAME) || mkdir $(PROD_PKGS)/$(PKG_NAME)'
	@scp $(DIST_DIR)/* $(PROD_USER):$(PROD_PKGS)/$(PKG_NAME)/
	@echo ""
	@echo "Done."
	@echo ""
