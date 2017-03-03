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
import errno
import hashlib
import json
import os

from const import BLOB_STORE_ROOT
from format_tools import Sha1Lookup
from utilities import ObjectJsonEncoder, only_files, hashfile, create_dirs, hash_copy_file

class ByteSequence(object):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    EMPTY_SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    def __init__(self, sha1=EMPTY_SHA1, size=0):
        self.sha1 = sha1
        self.size = size

    def get_sha1(self):
        """Returns the SHA-1 hash of the ByteSequence, use as an id."""
        return self.sha1

    def get_size(self):
        """Return the size of the ByteSequence in bytes."""
        return self.size

    def __str__(self):
        ret_val = []
        ret_val.append("ByteSequence : [sha1=")
        ret_val.append(self.sha1)
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def default_instance(cls):
        """ Returns the default instance, an empty byte sequence. """
        return ByteSequence()

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for ByteSequence. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            byte_seq = obj[cls_name]
            return cls(byte_seq['sha1'], byte_seq['size'])
        return obj

class BlobStore(object):
    """ Hash identified store for binary objects. """
    __blobpath__ = 'blobs/'
    __metapath__ = 'meta/'
    __blobmeta__ = __metapath__ + 'blob.json'
    def __init__(self, root, persist=True):
        self.root = root
        self.size = 0
        self.blobs = collections.defaultdict(dict)
        self.is_persistent = persist
        self.initialise()

    def get_blob(self, sha1):
        """ Get a blob by it's key. """
        return self.blobs.get(sha1, None)

    def get_blob_count(self):
        """ Returns the number of blobs in the store. """
        return len(self.blobs)

    def get_size(self):
        """ Returns the number of bytes in the store. """
        if self.size < 1:
            self.size = self.calculate_size()
        return self.size

    def is_store_persistent(self):
        """ Return true if the blob store is persistent. """
        return self.is_persistent

    def add_file(self, path, sha1=None):
        """ Adds file at path to corpus and returns the sha1. """
        if not os.path.isfile(path):
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        if sha1 is None:
            with open(path, 'rb') as src:
                sha1 = hashfile(src, hashlib.sha1())
        if not sha1 in self.blobs.keys():
            dest_path = self.get_blob_path(sha1)
            with open(path, 'rb') as src:
                with open(dest_path, 'w+') as dest:
                    calc_sha1 = hash_copy_file(src, dest, hashlib.sha1())
            if calc_sha1 != sha1:
                raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                              'SHA1 failure copying {}.'.format(path))
            size = os.path.getsize(path)
            self.blobs.update({calc_sha1 : ByteSequence(calc_sha1, size)})
        return sha1

    def hash_check(self):
        """Performs a hash check of all BLOBs in the store"""
        blob_root = self.root + self.__blobpath__
        fnamelst = only_files(blob_root)
        tuples_to_check = [(fname, hashfile(open(blob_root + fname, 'rb'),
                                            hashlib.sha1())) for fname in fnamelst]
        for to_check in tuples_to_check:
            if to_check[0] != to_check[1]:
                print "Digest mis-maatch for file " + blob_root + to_check[0] + \
                ", calculated: " + to_check[1]

    def get_root(self):
        """Get the root directory for the BLOB store"""
        return self.root

    def get_blob_path(self, sha1):
        """Returns the file path of a the BLOB called blob_name"""
        return self.root + self.__blobpath__ + sha1

    def calculate_size(self):
        """ Returns the recalculated total size of the blob store but doesn't
        update the cls.SIZE attribute.
        """
        total_size = 0
        for byte_seq in self.blobs.values():
            total_size += byte_seq.get_size()
        return total_size

    def initialise(self):
        """ If persist_to exists, tries to load a serialised lookup table from it.
        Populates lookup table and saves to persist_to if persist_to doesn't exist.
        """
        self.check_and_create_root()

        if not self.is_persistent:
            # No persist requested, populate the dictionary
            self.reload_blobs()
            return

        persist_to = self.get_blob_meta_path()
        if os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            with open(persist_to, 'r') as lookup_file:
                self.load(lookup_file)
        else:
            self.reload_blobs()
            with open(persist_to, 'w+') as lookup_file:
                self.save(lookup_file)

    def get_blob_meta_path(self):
        """ Returns the full path of the Blob metadata file. """
        return self.root + self.__class__.__blobmeta__

    def persist(self):
        """ Persists the current state of the internal blobstore dictionary
        to the default location, overwriting the existing state.
        """
        persist_to = self.get_blob_meta_path()
        with open(persist_to, 'w+') as lookup_file:
            self.save(lookup_file)

    def save(self, dest):
        """ Serialise the datacentre lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(self.blobs, dest, cls=ObjectJsonEncoder)

    def load(self, src):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        self.blobs.clear()
        self.size = 0
        self.blobs = json.load(src, object_hook=ByteSequence.json_decode)

    def check_and_create_root(self):
        """ Checks that the root dirs for the BlobStore exist and makes
        them if missing.
        """
        dirs = ['', self.__blobpath__, self.__metapath__]
        for directory in dirs:
            create_dirs(self.root + directory)

    def reload_blobs(self):
        """ Clears the lookup dictionary and loads the details of blob files
        from scratch.
        """
        self.blobs.clear()
        blob_root = self.root + self.__blobpath__
        for blob_name in only_files(blob_root):
            path = blob_root + blob_name
            byte_seq = ByteSequence(Sha1Lookup.get_sha1(blob_name), os.path.getsize(path))
            self.blobs.update({blob_name : byte_seq})

def main():
    """
    Main method entry point, parses DOIs from Datacite and outputs to
    STDOUT.
    """
    blob_store = BlobStore(BLOB_STORE_ROOT, persist=False)
    print 'Blobstore contains {} blobs, {} bytes'.format(blob_store.get_blob_count(), blob_store.get_size())

if __name__ == "__main__":
    main()
