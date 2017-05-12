#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Setup for the JISC RDSS Format Tools"""

import codecs
import os
import re

from setuptools import setup

def read(*parts):
    """ Read a file and return the contents. """
    path = os.path.join(os.path.dirname(__file__), *parts)
    with codecs.open(path, encoding='utf-8') as fobj:
        return fobj.read()

def find_version(version_id, *file_paths):
    """Parse the module version from corptest/__init__.py."""
    version_file = read(*file_paths)
    version_match = re.search(r"^{} = ['\"]([^'\"]*)['\"]".format(version_id), version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

INSTALL_REQUIRES = [
    'setuptools',
    'flask == 0.12.1',
    'flask_sqlalchemy == 2.2',
    'sqlalchemy == 1.1.9',
    'six == 1.10.0',
    'scandir == 1.5',
    'requests == 2.13.0',
    'numpy == 1.12.1',
    'opf-fido == ' + find_version('__opf_fido_version__', 'corptest', 'corptest.py'),
    'python-magic == ' + find_version('__python_magic_version__', 'corptest', 'corptest.py'),
    'lxml == 3.7.3',
    'boto3 == 1.4.4',
    'tzlocal',
]

SETUP_REQUIRES = [
    'pytest-runner',
]

TEST_REQUIRES = [
    'pytest',
]

setup(name='jiscrdss-fmtsniff',
      version=find_version('__version__', 'corptest', 'corptest.py'),
      description='JISC Research Data Shared Service : Format identification toolset.',
      long_description='JISCRDSS Python tools to test format identification tools \
                        across test corpora, primarily held on Amazon S3 storage.',
      url="http://github.com/carlwilson/fmt-sniff",
      author='Carl Wilson',
      author_email='carl@openpreservation.org',
      license="GPL",
      classifiers=[
          'Intended Audience :: Archivists',
          'License :: OSI Approved :: GPL License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
      ],
      install_requires=INSTALL_REQUIRES,
      setup_requires=SETUP_REQUIRES,
      tests_require=TEST_REQUIRES,
      packages=['corptest'],
      package_data={
          'corptest': ['*.*', 'conf/*.*'],
      },
      keywords="mime magic",
      test_suite='test',
     )
