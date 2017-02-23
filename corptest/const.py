#!/usr/bin/python
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

import datetime

SOURCE_ROOT = 'http://rdss-test-data.s3-eu-west-1.amazonaws.com/'
BLOB_STORE_ROOT = '/vagrant_data/blobstore/'
S3_META = '/vagrant_data/s3/'
DOI_STORE = '/vagrant_data/doi/lookup.json'
JISC_BUCKET = 'testdata.researchdata.alpha.jisc.ac.uk'
RESULTS_ROOT = '/vagrant_data/results/'
DATACITE_PAGES = range(1, 41)
DATACITE_HTML_ROOT = 'https://search.datacite.org'
DATACITE_PAGE_QUERY = '/data-centers?page='
EPILOG = """
JISC (https://www.jisc.ac.uk)
Open Preservation Foundation (http://www.openpreservation.org)
See License.txt for license information.
Author: Carl Wilson (OPF), 2016-17
This work was funded by the JISC Research Data Shared Service project
You can read more about this at https://www.jisc.ac.uk/rd/projects/research-data-shared-service"""

class AS3EleFields(object):
    """Field names and default for AS3 Element type"""
    KEY = 'key'
    ETAG = 'etag'
    SIZE = 'size'
    MODIFIED = 'last_modified'
    DEFAULT = {
        KEY: '',
        ETAG: '',
        SIZE: 0,
        MODIFIED: datetime.date.today()
    }

    @classmethod
    def default(cls):
        """Return the default instance"""
        return cls.DEFAULT

class AS3Tags(object):
    """XML tag names for AS3 element"""
    # Parent tags
    RESULTS = 'ListBucketResult'
    CONTENTS = 'Contents'
    PARENTS = [RESULTS, CONTENTS]
    # Tags for mapping
    KEY = 'Key'
    MODIFIED = 'LastModified'
    ETAG = 'ETag'
    SIZE = 'Size'


class AS3TagMap(object):
    """Lookup tag map of XML tag values"""
    LOOKUP = {
        AS3Tags.KEY: AS3EleFields.KEY,
        AS3Tags.MODIFIED: AS3EleFields.MODIFIED,
        AS3Tags.ETAG: AS3EleFields.ETAG,
        AS3Tags.SIZE: AS3EleFields.SIZE
    }
