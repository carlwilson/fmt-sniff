#!/usr/bin/env python
# coding=UTF-8
#
# JISC Format Sniffing
# Copyright (C) 2016
# All rights reserved.
#
# This code is distributed under the terms of the GNU General Public
# License, Version 3. See the text file "COPYING" for further details
# about the terms of this license.
#
"""Constants used across corptest modules"""

SOURCE_ROOT = 'http://rdss-test-data.s3-eu-west-1.amazonaws.com/'
JISC_BUCKET = 'testdata.researchdata.alpha.jisc.ac.uk'
RDSS_ROOT = '/vagrant_data/'
RDSS_CACHE = ''.join([RDSS_ROOT, 'cache/'])
BLOB_STORE_ROOT = ''.join([RDSS_ROOT, 'blobstore/'])
S3_META = ''.join([RDSS_ROOT, 's3/'])
DOI_STORE = ''.join([RDSS_ROOT, 'doi/lookup.json'])
RESULTS_ROOT = ''.join([RDSS_ROOT, 'results/'])
DATACITE_PAGES = range(1, 4)
DATACITE_HTML_ROOT = 'https://search.datacite.org'
DATACITE_BL_QUERY = '/data-centers?member-id=bl&page='
ENV_CONF_PROFILE = 'JISC_FFA_CONF_PROFILE'
ENV_CONF_FILE = 'JISC_FFA_CONF_FILE'
EPILOG = """
JISC (https://www.jisc.ac.uk)
Open Preservation Foundation (http://www.openpreservation.org)
See License.txt for license information.
Author: Carl Wilson (OPF), 2016-17
This work was funded by the JISC Research Data Shared Service project
You can read more about this at https://www.jisc.ac.uk/rd/projects/research-data-shared-service"""
