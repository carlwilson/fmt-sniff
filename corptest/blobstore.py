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
# http://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
"""Classes for binary object store"""
import collections
import hashlib
import os
import sys
import urllib
from formats import MimeType, MagicType, PronomId

class BlobStore(object):
    """Binary Large Object Store class definition"""
    FORMAT_INFO = collections.defaultdict(dict)
    def __init__(self, rootDir):
        if not os.path.isdir(rootDir):
            os.makedirs(rootDir)
        self.root = rootDir

    def add_s3_ele_from_index(self, root_url, ele):
        """Add a new BLOB from an S3 element"""
        if not ele.is_file():
            return
        filename = self.path_from_s3_ele(ele)
        if os.path.isfile(filename):
            return
        location = root_url + ele.get_key().encode("utf-8")
        downloader = urllib.URLopener()
        downloader.retrieve(location, filename)

    def add_s3_ele_from_bucket(self, bucket, ele):
        """Add a new BLOB from an S3 element"""
        if not ele.is_file():
            return
        filename = self.path_from_s3_ele(ele)
        if os.path.isfile(filename):
            return
        bucket.download_file(ele.get_key(), filename)

    def path_from_s3_ele(self, ele):
        """Returns the fixed file path created from ele"""
        return self.root + ele.get_etag()

    def get_root(self):
        """Get the root directory for the BLOB store"""
        return self.root

    def get_blob_names(self):
        """Returns a list of names for all BLOBS in the store"""
        onlyfiles = [f for f in os.listdir(self.root) if os.path.isfile(os.path.join(self.root, f))]
        return onlyfiles

    def get_blob_path(self, blob_name):
        """Returns the file path of a the BLOB called blob_name"""
        return self.root + blob_name

    def hash_check(self):
        """Performs a hash check of all BLOBs in the store"""
        fnamelst = self.get_blob_names()
        tuples_to_check = [(fname, hashfile(open(self.root + fname, 'rb'),
                                            hashlib.md5())) for fname in fnamelst]
        for to_check in tuples_to_check:
            if to_check[0] != to_check[1]:
                print "Digest mis-maatch for file " + self.root + to_check[0] + \
                ", calculated: " + to_check[1]

    def identify_contents(self):
        """Perform format identification for all BLOBs in the store using
            * libmagic
            * Apache Tika
            * FIDO
        """
        for blob_name in self.get_blob_names():
            mime_type = MimeType.from_file_by_magic(self.get_blob_path(blob_name))
            magic_type = MagicType.from_file_by_magic(self.get_blob_path(blob_name))
            # tika_type = MimeType.from_file_by_tika(self.get_blob_path(blob_name))
            fido_types = PronomId.from_file_by_fido(self.get_blob_path(blob_name))
            self.FORMAT_INFO[blob_name]['magic'] = magic_type
            self.FORMAT_INFO[blob_name]['magic_mime'] = mime_type
            # self.FORMAT_INFO[blob_name]['tika'] = tika_type
            self.FORMAT_INFO[blob_name]['fido'] = fido_types

    def load_corpus(self, corpus, bucket):
        """Loads the contents of corpus into the BLOB store"""
        total_eles = int(corpus.get_element_count())
        ele_count = 1
        downloaded_bytes = 0
        print ("Starting courpus download of {0:d} items " + \
               "totalling {1:d} bytes.").format(total_eles, corpus.get_total_size())
        for element in corpus.get_elements():
            print ('Downloading item number {0:d}/{1:d}, {2:d} of ' + \
            '{3:d} bytes\r').format(ele_count, total_eles,
                                    downloaded_bytes,
                                    corpus.get_total_size()),
            sys.stdout.flush()
            self.add_s3_ele_from_bucket(bucket, element)
            downloaded_bytes += element.get_size()
            ele_count += 1
        print chr(27) + "[2K"
        print ('Downloaded {0:d} items totalling {1:d} bytes from ' + \
               'corpus.').format(total_eles, corpus.get_total_size())

    @classmethod
    def get_format_info(cls):
        """Get the collections of format information"""
        return cls.FORMAT_INFO

def hashfile(afile, hasher, blocksize=65536):
    """Calculates the digest of afile using the supplied hasher which should
    implement update(buffer) and hexdigest() methods.
    """
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()
