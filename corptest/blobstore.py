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
import logging
import os
from os import path

from corptest.model import ByteSequence
from corptest.utilities import check_param_not_none, sha1_path, sha1_copy_by_path
from corptest.utilities import only_files, create_dirs

from corptest import APP
RDSS_ROOT = APP.config.get('RDSS_ROOT')

class Sha1Lookup(object):
    """ Look up class for serialsed sha1sum() results. """
    sha1_lookup = collections.defaultdict(dict)

    @classmethod
    def initialise(cls, source_path=os.path.join(RDSS_ROOT, 'blobstore-sha1s.txt')):
        """ Clear and load the lookup table from the supplied or default source_path. """
        cls.sha1_lookup.clear()
        if path.isfile(source_path):
            cls._update_lookup_from_path(source_path)

    @classmethod
    def get_sha1(cls, etag):
        """ Retrieve and return a hex SHA1 value by etag. """
        return cls.sha1_lookup.get(etag, None)

    @classmethod
    def _update_lookup_from_path(cls, source_path):
        with open(source_path) as src_file:
            for line in src_file:
                parts = line.split(' ')
                etag = parts[2][2:-1]
                sha1 = parts[0]
                cls.sha1_lookup.update({etag : sha1})

class BlobStore(object):
    """ Hash identified store for binary objects. """
    __blobpath = 'blobs/'
    def __init__(self, root):
        self.__root = root
        self.__size = 0
        self.__blobs = collections.defaultdict(dict)
        logging.warning("Initialising BlobStore")
        self.__initialise()

    def get_blob(self, sha1):
        """ Get a blob by it's key. """
        check_param_not_none(sha1, "sha1")
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
        check_param_not_none(blobs, "blobs")
        self.blobs.clear()
        self.__size = 0
        self.__blobs = blobs

    def add_file(self, file_path, sha1=None):
        """ Adds file at path to corpus and returns the sha1. """
        check_param_not_none(file_path, "file_path")
        byte_sequence = ByteSequence.from_file(file_path)
        if sha1 is not None and sha1 != byte_sequence.sha1:
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                          'Supplied hash {} does not match {} calculated from {}.'\
                          .format(sha1,
                                  byte_sequence.sha1,
                                  file_path))
        sha1 = byte_sequence.sha1
        if sha1 not in self.blobs.keys():
            dest_path = self.get_blob_path(sha1)
            calc_sha1 = sha1_copy_by_path(file_path, dest_path)
            if calc_sha1 != sha1:
                raise IOError(errno.ENOENT, os.strerror(errno.ENOENT),
                              'SHA1 failure copying {}.'.format(file_path))
            self.blobs.update({byte_sequence.sha1 : byte_sequence})

        return byte_sequence

    @property
    def blob_root(self):
        """ Return the BlobStore's root directory. """
        return self.__root + self.__blobpath

    def clear(self):
        """ Clears all blobs from a store. """
        for blob_name in only_files(self.blob_root):
            file_path = self.blob_root + blob_name
            os.remove(file_path)
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
        check_param_not_none(sha1, "sha1")
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
        logging.warning("Checking BlobStore root")
        self.__check_and_create_root()
        logging.warning("Reloading BlobStore")
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
            file_path = self.blob_root + blob_name
            size = os.stat(file_path).st_size
            byte_seq = ByteSequence(blob_name, size)
            self.blobs.update({byte_seq.sha1 : byte_seq})

def main():
    """
    Main method entry point, parses DOIs from Datacite and outputs to
    STDOUT.
    """
    blob_store = BlobStore(os.path.join(RDSS_ROOT, 'blobstore'))
    print('Blobstore contains {} blobs, {} bytes'.format(blob_store.blob_count,
                                                         blob_store.size))

if __name__ == "__main__":
    main()
