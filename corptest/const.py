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
BLOB_STORE_ROOT = '/home/cfw/arch/data/samp/JISC/blobstore/'
JISC_BUCKET = 'testdata.researchdata.alpha.jisc.ac.uk'


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
