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
# http://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
"""Classes for binary object store"""
import collections
import errno
import json
import os

from corptest.const import BLOB_STORE_ROOT
from corptest.utilities import sha1_path, sha1_string, sha1_copy_by_path
from corptest.utilities import ObjectJsonEncoder, only_files, create_dirs

class ByteSequence(object):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    EMPTY_SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    def __init__(self, sha1=EMPTY_SHA1, size=0):
        self.__sha1 = sha1
        self.__size = size

    @property
    def sha1(self):
        """Returns the SHA-1 hash of the ByteSequence, use as an id."""
        return self.__sha1

    @property
    def size(self):
        """Return the size of the ByteSequence in bytes."""
        return self.__size

    def __key(self):
        return (self.sha1, self.size)

    def __eq__(self, other):
        """ Define an equality test for ByteSequence """
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        """ Define an inequality test for ByteSequence """
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

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
        sha1 = sha1_path(source_path)
        size = os.path.getsize(source_path)
        return cls(sha1, size)

    @classmethod
    def from_string(cls, source):
        """ Creates a new ByteStream instance from the supplied string. """
        sha1 = sha1_string(source)
        return cls(sha1, len(source))

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for ByteSequence. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            byte_seq = obj[cls_name]
            return cls(byte_seq['_ByteSequence__sha1'], byte_seq['_ByteSequence__size'])
        return obj

class BlobStore(object):
    """ Hash identified store for binary objects. """
    __blobpath = 'blobs/'
    def __init__(self, root):
        self.__root = root
        self.__size = 0
        self.__blobs = collections.defaultdict(dict)
        self.__initialise()

    def get_blob(self, sha1):
        """ Get a blob by it's key. """
        return self.blobs.get(sha1, None)

    @property
    def blob_count(self):
        """ Returns the number of blobs in the store. """
        return len(self.__blobs)

    @property
    def blobs(self):
        """ Returns the number of blobs in the store. """
        return self.__blobs

    @property
    def size(self):
        """ Returns the number of bytes in the store. """
        if self.__size < 1:
            self.__size = self.__calculate_size()
        return self.__size

    @property
    def root(self):
        """Get the root directory for the BLOB store"""
        return self.__root

    def replace_blobs(self, blobs):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        self.blobs.clear()
        self.__size = 0
        self.__blobs = blobs

    def add_file(self, path, sha1=None):
        """ Adds file at path to corpus and returns the sha1. """
        byte_sequence = ByteSequence.from_file(path)
        if sha1 is not None and sha1 != byte_sequence.sha1:
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                          'Supplied hash {} does not match {} calculated from {}.'\
                          .format(sha1,
                                  byte_sequence.sha1,
                                  path))
        sha1 = byte_sequence.sha1
        if sha1 not in self.blobs.keys():
            dest_path = self.get_blob_path(sha1)
            calc_sha1 = sha1_copy_by_path(path, dest_path)
            if calc_sha1 != sha1:
                raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                              'SHA1 failure copying {}.'.format(path))
            self.blobs.update({byte_sequence.sha1 : byte_sequence})

        return byte_sequence

    @property
    def blob_root(self):
        """ Return the BlobStore's root directory. """
        return self.__root + self.__blobpath

    def clear(self):
        """ Clears all blobs from a store. """
        for blob_name in only_files(self.blob_root):
            path = self.blob_root + blob_name
            os.remove(path)
        self.blobs.clear()
        self.__size = 0

    def hash_check(self):
        """Performs a hash check of all BLOBs in the store"""
        fnamelst = only_files(self.blob_root)
        tuples_to_check = [(fname, sha1_path(self.blob_root + fname)) for fname in fnamelst]
        retval = True
        for to_check in tuples_to_check:
            if to_check[0] != to_check[1]:
                print("Digest mis-maatch for file " + self.blob_root + to_check[0] + \
                ", calculated: " + to_check[1])
                retval = False
        return retval

    def get_blob_path(self, sha1):
        """Returns the file path of a the BLOB called blob_name"""
        return self.blob_root + sha1

    def __calculate_size(self):
        """ Returns the recalculated total size of the blob store but doesn't
        update the cls.SIZE attribute.
        """
        total_size = 0
        for byte_seq in self.blobs.values():
            total_size += byte_seq.size
        return total_size

    def __initialise(self):
        """ If persist_to exists, tries to load a serialised lookup table from it.
        Populates lookup table and saves to persist_to if persist_to doesn't exist.
        """
        self.__check_and_create_root()
        self.reload_blobs()
        return

    def __check_and_create_root(self):
        """ Checks that the root dirs for the BlobStore exist and makes
        them if missing.
        """
        dirs = ['', self.__blobpath]
        for directory in dirs:
            create_dirs(self.root + directory)

    def reload_blobs(self):
        """ Clears the lookup dictionary and loads the details of blob files
        from scratch.
        """
        self.blobs.clear()
        for blob_name in only_files(self.blob_root):
            path = self.blob_root + blob_name
            byte_seq = ByteSequence.from_file(path)
            self.blobs.update({byte_seq.sha1 : byte_seq})

class PersistentBlobStore(object):
    """ Persistent BlobStore that saves blob data to a JSON file. """
    __metapath = 'meta/'
    __blobmeta = __metapath + 'blob.json'

    def __init__(self, root):
        self.__blobstore = BlobStore(root)
        self.__initialise()

    def get_blob(self, sha1):
        """ Get a blob by it's key. """
        return self.__blobstore.get_blob(sha1)

    @property
    def blob_count(self):
        """ Returns the number of blobs in the store. """
        return self.__blobstore.blob_count

    @property
    def get_size(self):
        """ Returns the number of bytes in the store. """
        return self.__blobstore.size

    def add_file(self, path, sha1=None):
        """ Add a file to the blobstore with optional SHA1 check. """
        return self.__blobstore.add_file(path, sha1)

    def __initialise(self):
        """ If persist_to exists, tries to load a serialised lookup table from it.
        Populates lookup table and saves to persist_to if persist_to doesn't exist.
        """

        persist_to = self.__get_blob_meta_path()
        if os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            with open(persist_to, 'r') as lookup_file:
                self.load(lookup_file)
        else:
            with open(persist_to, 'w+') as lookup_file:
                self.save(lookup_file)

    def __get_blob_meta_path(self):
        """ Returns the full path of the Blob metadata file. """
        return self.__blobstore.root + self.__blobmeta

    def persist(self):
        """ Persists the current state of the internal blobstore dictionary
        to the default location, overwriting the existing state.
        """
        persist_to = self.__get_blob_meta_path()
        with open(persist_to, 'w+') as lookup_file:
            self.save(lookup_file)

    def save(self, dest):
        """ Serialise the datacentre lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(self.__blobstore.blobs, dest, cls=ObjectJsonEncoder)

    def load(self, src):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        blobs = json.load(src, object_hook=ByteSequence.json_decode)
        self.__blobstore.replace_blobs(blobs)


def main():
    """
    Main method entry point, parses DOIs from Datacite and outputs to
    STDOUT.
    """
    blob_store = BlobStore(BLOB_STORE_ROOT)
    print('Blobstore contains {} blobs, {} bytes'.format(blob_store.blob_count,
                                                         blob_store.size))

if __name__ == "__main__":
    main()
