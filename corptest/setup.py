#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(name='python-fmtsniff',
      description='Format sniffing application developed for JISC Research Data',
      author='Carl Wilson',
      author_email='carl@openpreservation.org',
      url="http://github.com/openpreserve/fmt-sniff",
      version='0.1.0',
      py_modules=['corptest'],
      long_description="""TODO.
""",
      keywords="mime magic",
      license="GPL",
      test_suite='test',
      classifiers=[
          'Intended Audience :: Archivists',
          'License :: OSI Approved :: GLP License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
      ],
      )
