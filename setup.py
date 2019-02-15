#! /usr/bin/env python

'''Setup file for genie.trafficgen Namespace Package

See:
    https://packaging.python.org/en/latest/distributing.html
'''

import os
from ciscodistutils import setup, find_packages, is_devnet_build
from ciscodistutils.tools import (read,
                                  version_info,
                                  generate_cython_modules)

_INTERNAL_SUPPORT = 'asg-genie-support@cisco.com'
_EXTERNAL_SUPPORT = 'pyats-support-ext@cisco.com'

_INTERNAL_LICENSE = 'Cisco Systems, Inc. Cisco Confidential',
_EXTERNAL_LICENSE = 'Apache 2.0'

_INTERNAL_URL = 'http://wwwin-pyats.cisco.com/cisco-shared/genietrafficgen/html/'
_EXTERNAL_URL = 'https://developer.cisco.com/site/pyats/'


# pyats support mailer
SUPPORT = _EXTERNAL_SUPPORT if is_devnet_build() else _INTERNAL_SUPPORT

# license statement
LICENSE = _EXTERNAL_LICENSE if is_devnet_build() else _INTERNAL_LICENSE

# project url
URL = _EXTERNAL_URL if is_devnet_build() else _INTERNAL_URL

# get version information
version, version_range = version_info('src', 'genie', 'trafficgen', '__init__.py')

install_requires=['setuptools', 'wheel', 'genie']

if is_devnet_build():
    install_requires.insert(0, 'pyats')
    install_requires.insert(0, 'ixnetwork')

def find_examples(*paths):
    '''finds all example files'''
    files = []

    for (dirpath, dirnames, filenames) in os.walk(os.path.join(*paths)):
        files.append((dirpath, [os.path.join(dirpath, f) for f in filenames]))

    return files

# launch setup
setup(
    name = 'genie.trafficgen',
    version = version,

    # descriptions
    description = 'Genie Library for traffic generator connection support',
    long_description = read('DESCRIPTION.rst'),

    # the project's main homepage.
    url = URL,

    # author details
    author = 'Cisco Systems Inc.',
    author_email = SUPPORT,

    # project licensing
    license = LICENSE,

    # see https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Build Tools',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],


    # project keywords
    keywords = 'genie traffic pyats cisco',

    # uses namespace package
    namespace_packages = ['genie'],

    # project packages
    packages = find_packages(where = 'src'),

    # project directory
    package_dir = {
        '': 'src',
    },

    # additional package data files that goes into the package itself
    package_data = {},

    # custom argument specifying the list of cythonized modules
    cisco_cythonized_modules = generate_cython_modules('src/'),

    # console entry point
    entry_points = {
        'pyats.utils.__legacy_imports__':
            'trafficgen = genie.trafficgen:_IMPORTMAP',
    },

    # package dependencies
    install_requires = install_requires,

    # any additional groups of dependencies.
    # install using: $ pip install -e .[dev]
    extras_require = {
        'dev': ['coverage',
                'restview',
                'Sphinx',
                'sphinxcontrib-napoleon',
                'sphinx-rtd-theme',
                'sphinxcontrib-mockautodoc'],
    },

    # external modules
    ext_modules = [],

    # any data files placed outside this package.
    # See: http://docs.python.org/3.4/distutils/setupscript.html
    # format:
    #   [('target', ['list', 'of', 'files'])]
    # where target is sys.prefix/<target>
    data_files = find_examples('examples'),

    # non zip-safe (never tested it)
    zip_safe = False,
)
