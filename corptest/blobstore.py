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
from utilities import hashfile, hashstring, hash_copy_file
from utilities import ObjectJsonEncoder, only_files, create_dirs

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

    def __eq__(self, other):
        """ Define an equality test for ByteSequence """
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        """ Define an inequality test for ByteSequence """
        return not self.__eq__(other)

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
    def from_file(cls, source_path):
        """ Creates a new ByteStream instance from the supplied file path. """
        if not os.path.isfile(source_path):
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT), source_path)
        with open(source_path, 'rb') as src:
            sha1 = hashfile(src, hashlib.sha1())
        size = os.path.getsize(source_path)
        return cls(sha1, size)

    @classmethod
    def from_string(cls, source):
        """ Creates a new ByteStream instance from the supplied string. """
        sha1 = hashstring(source, hashlib.sha1())
        return cls(sha1, len(source))

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
    def __init__(self, root):
        self.root = root
        self.size = 0
        self.blobs = collections.defaultdict(dict)
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

    def get_root(self):
        """Get the root directory for the BLOB store"""
        return self.root

    def replace_blobs(self, blobs):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        self.blobs.clear()
        self.size = 0
        self.blobs = blobs

    def add_file(self, path, sha1=None):
        """ Adds file at path to corpus and returns the sha1. """
        byte_sequence = ByteSequence.from_file(path)
        if sha1 is not None and sha1 != byte_sequence.get_sha1():
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                          'Supplied hash {} does not \
                           match {} calculated from {}.'.format(sha1,
                                                                byte_sequence.get_sha1(),
                                                                path))
        if sha1 not in self.blobs.keys():
            dest_path = self.get_blob_path(sha1)
            with open(path, 'rb') as src:
                with open(dest_path, 'w+') as dest:
                    calc_sha1 = hash_copy_file(src, dest, hashlib.sha1())
            if calc_sha1 != sha1:
                raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                              'SHA1 failure copying {}.'.format(path))
            self.blobs.update({byte_sequence.get_sha1() : byte_sequence})

        return byte_sequence

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
        self.reload_blobs()
        return

    def check_and_create_root(self):
        """ Checks that the root dirs for the BlobStore exist and makes
        them if missing.
        """
        dirs = ['', self.__blobpath__]
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

class PersistentBlobStore(object):
    """ Persistent BlobStore that saves blob data to a JSON file. """
    __metapath__ = 'meta/'
    __blobmeta__ = __metapath__ + 'blob.json'

    def __init__(self, root):
        self.blobstore = BlobStore(root)
        self.initialise()

    def get_blob(self, sha1):
        """ Get a blob by it's key. """
        return self.blobstore.get_blob(sha1)

    def get_blob_count(self):
        """ Returns the number of blobs in the store. """
        return self.blobstore.get_blob_count()

    def get_size(self):
        """ Returns the number of bytes in the store. """
        return self.blobstore.get_size()

    def add_file(self, path, sha1=None):
        """ Add a file to the blobstore with optional SHA1 check. """
        return self.blobstore.add_file(path, sha1)

    def initialise(self):
        """ If persist_to exists, tries to load a serialised lookup table from it.
        Populates lookup table and saves to persist_to if persist_to doesn't exist.
        """

        persist_to = self.get_blob_meta_path()
        if os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            with open(persist_to, 'r') as lookup_file:
                self.load(lookup_file)
        else:
            with open(persist_to, 'w+') as lookup_file:
                self.save(lookup_file)

    def get_blob_meta_path(self):
        """ Returns the full path of the Blob metadata file. """
        return self.blobstore.get_root() + self.__class__.__blobmeta__

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
        json.dump(self.blobstore.blobs, dest, cls=ObjectJsonEncoder)

    def load(self, src):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        blobs = json.load(src, object_hook=ByteSequence.json_decode)
        self.blobstore.replace_blobs(blobs)


def main():
    """
    Main method entry point, parses DOIs from Datacite and outputs to
    STDOUT.
    """
    blob_store = BlobStore(BLOB_STORE_ROOT)
    print 'Blobstore contains {} blobs, {} bytes'.format(blob_store.get_blob_count(),
                                                         blob_store.get_size())

if __name__ == "__main__":
    main()
