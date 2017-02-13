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

def find_version(*file_paths):
    """Parse the module version from corptest/__init__.py."""
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


install_requires = [
    'setuptools',
    'six == 1.10.0',
]


setup_requires = [
    'pytest-runner',
]


tests_require = [
    'pytest',
]


setup(name='jiscrdss-fmtsniff',
      description='JISC Research Data Shared Service : Format identification toolset.',
      long_description='JISCRDSS Python tools to test format identification tools across test corpora, primarily held on Amazon S3 storage.',
      author='Carl Wilson',
      author_email='carl@openpreservation.org',
      url="http://github.com/carlwilson/fmt-sniff",
      version=find_version('corptest', '__init__.py'),
      install_requires=install_requires,
      setup_requires=setup_requires,
      tests_require=tests_require,
      packages=['corptest'],
      package_data={'corptest': ['*.*', 'conf/*.*']},
      keywords="mime magic",
      license="GPL",
      test_suite='test',
      entry_points={'console_scripts': [
          'corptest = corptest.scraper:main',
          'doi-parse = corptest.doi:main',
      ]},
      classifiers=[
          'Intended Audience :: Archivists',
          'License :: OSI Approved :: GPL License',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
      ],
     )
