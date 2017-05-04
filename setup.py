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

INSTALL_REQUIRES = [
    'setuptools',
    'flask',
    'flask_sqlalchemy',
    'six == 1.10.0',
    'scandir',
    'requests == 2.13.0',
    'numpy == 1.12.1',
    'opf-fido==1.3.5',
    'python-magic==0.4.13',
    'lxml==3.7.3',
    'boto3==1.4.4',
]

SETUP_REQUIRES = [
    'pytest-runner',
]

TEST_REQUIRES = [
    'pytest',
]

setup(name='jiscrdss-fmtsniff',
      version=find_version('corptest', '__init__.py'),
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
      entry_points={
          'console_scripts': [
              'analyse = corptest.analyser:main',
              'blob-tools = corptest.blobstore:main',
              'doi-tools = corptest.doi:main',
              's3-tools = corptest.s3_corpora:main',
          ],
      },
     )
