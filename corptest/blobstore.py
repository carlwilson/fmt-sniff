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
import json
import os

from const import BLOB_STORE_ROOT
from formats import MimeType, MagicType, PronomId
from format_tools import Sha1Lookup
from utilities import ObjectJsonEncoder, only_files, hashfile, create_dirs, hash_copy_file

class ByteSequence(object):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    def __init__(self, size, sha_1):
        self.size = size
        self.sha_1 = sha_1

    def get_size(self):
        """Return the size of the ByteSequence in bytes."""
        return self.size

    def get_sha1(self):
        """Returns the SHA-1 hash of the ByteSequence, use as an id."""
        return self.sha_1

    def __str__(self):
        ret_val = []
        ret_val.append("ByteSequence : [size=")
        ret_val.append(str(self.size))
        ret_val.append(", sha_1=")
        ret_val.append(self.sha_1)
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for ByteSequence. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            byte_seq = obj[cls_name]
            return cls(byte_seq['size'], byte_seq['sha_1'])
        return obj

class Blob(object):
    """ Wrapper for blobs stored in the blob store. """
    def __init__(self, key, path, byte_seq):
        self.key = key
        self.path = path
        self.byte_sequence = byte_seq

    def get_key(self):
        """ Get the key for the Blob. """
        return self.key

    def get_path(self):
        """ Get the path to the file for the Blob. """
        return self.path

    def get_byte_sequence(self):
        """ Get the ByteSequence details. """
        return self.byte_sequence

    def __str__(self):
        ret_val = []
        ret_val.append("Blob : [key=")
        ret_val.append(self.key)
        ret_val.append(", path=")
        ret_val.append(self.path)
        ret_val.append(", byte_sequence=")
        ret_val.append(str(self.byte_sequence))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for ByteSequence. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            blob = obj[cls_name]
            return cls(blob['key'], blob['path'],
                       ByteSequence.json_decode(blob['byte_sequence']))
        return obj

class BlobStore(object):
    """ Hash identified store for binary objects. """
    __blobpath__ = 'blobs/'
    __metapath__ = 'meta/'
    __blobmeta__ = __metapath__ + 'blob.json'
    SIZE = 0
    ROOT = None
    BLOBS = collections.defaultdict(dict)
    SHA1_LOOKUP = collections.defaultdict(dict)
    FORMAT_INFO = collections.defaultdict(dict)

    @classmethod
    def get_blob(cls, key):
        """ Get a blob by it's key. """
        return cls.BLOBS.get(key, None)

    @classmethod
    def get_blob_by_sha1(cls, sha1):
        """ Get a blob by it's sha1. """
        key = cls.SHA1_LOOKUP.get(sha1, None)
        if key is None:
            return None
        return cls.BLOBS.get(key, None)

    @classmethod
    def get_blob_count(cls):
        """ Returns the number of blobs in the store. """
        return len(cls.BLOBS)

    @classmethod
    def get_total_blob_size(cls):
        """ Returns the number of bytes in the store. """
        if cls.SIZE < 1:
            cls.SIZE = cls.recalc_size()
        return cls.SIZE

    @classmethod
    def add_file(cls, path, key, sha1=None):
        """ Adds file at path to corpus and returns the sha1. """
        if key in cls.BLOBS or not os.path.isfile(path):
            raise IOError
        dest_path = cls.get_blob_path(sha1)
        with open(path, 'rb') as src:
            with open(dest_path, 'w+') as dest:
                calc_sha1 = hash_copy_file(src, dest, hashlib.sha1())
        size = os.path.getsize(path)
        cls.BLOBS.update({key : Blob(key, dest_path, ByteSequence(size, calc_sha1))})
        cls.SHA1_LOOKUP.update({calc_sha1 : key})
        return sha1

    @classmethod
    def update_sha1_lookup(cls):
        """Recalcs the sha1 to key lookup table."""
        cls.SHA1_LOOKUP.clear()
        for key in cls.BLOBS.keys():
            blob = cls.BLOBS.get(key)
            cls.SHA1_LOOKUP.update({blob.byte_sequence.sha_1 : key})

    @classmethod
    def hash_check(cls):
        """Performs a hash check of all BLOBs in the store"""
        blob_root = cls.ROOT + cls.__blobpath__
        fnamelst = only_files(blob_root)
        tuples_to_check = [(fname, hashfile(open(blob_root + fname, 'rb'),
                                            hashlib.md5())) for fname in fnamelst]
        for to_check in tuples_to_check:
            if to_check[0] != to_check[1]:
                print "Digest mis-maatch for file " + blob_root + to_check[0] + \
                ", calculated: " + to_check[1]

    @classmethod
    def get_root(cls):
        """Get the root directory for the BLOB store"""
        return cls.ROOT

    @classmethod
    def get_blob_path(cls, blob_name):
        """Returns the file path of a the BLOB called blob_name"""
        return cls.ROOT + cls.__blobpath__ + blob_name

    @classmethod
    def identify_contents(cls):
        """Perform format identification for all BLOBs in the store using
            * libmagic
            * Apache Tika
            * FIDO
        """
        blob_root = cls.ROOT + cls.__blobpath__
        for blob_name in only_files(blob_root):
            mime_type = MimeType.from_file_by_magic(cls.get_blob_path(blob_name))
            magic_type = MagicType.from_file_by_magic(cls.get_blob_path(blob_name))
            # tika_type = MimeType.from_file_by_tika(self.get_blob_path(blob_name))
            fido_types = PronomId.from_file_by_fido(cls.get_blob_path(blob_name))
            cls.FORMAT_INFO[blob_name]['magic'] = magic_type
            cls.FORMAT_INFO[blob_name]['magic_mime'] = mime_type
            # self.FORMAT_INFO[blob_name]['tika'] = tika_type
            cls.FORMAT_INFO[blob_name]['fido'] = fido_types

    @classmethod
    def recalc_size(cls):
        """ Returns the recalculated total size of the blob store but doesn't
        update the cls.SIZE attribute.
        """
        total_size = 0
        for val in cls.BLOBS.values():
            total_size += val.get_byte_sequence().get_size()
        return total_size

    @classmethod
    def initialise(cls, root_dir, persist=False):
        """ If persist_to exists, tries to load a serialised lookup table from it.
        Populates lookup table and saves to persist_to if persist_to doesn't exist.
        """
        cls.check_and_create_root(root_dir)

        if not persist:
            # No persist requested, populate the dictionary
            cls.reload_blobs()
            return

        persist_to = cls.get_blob_meta_path()
        if os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            with open(persist_to, 'r') as lookup_file:
                cls.load(lookup_file)
        else:
            cls.reload_blobs()
            with open(persist_to, 'w+') as lookup_file:
                cls.save(lookup_file)

    @classmethod
    def get_blob_meta_path(cls):
        """ Returns the full path of the Blob metadata file. """
        return cls.ROOT + cls.__blobmeta__

    @classmethod
    def persist(cls):
        """ Persists the current state of the internal blobstore dictionary
        to the default location, overwriting the existing state.
        """
        persist_to = cls.get_blob_meta_path()
        with open(persist_to, 'w+') as lookup_file:
            cls.save(lookup_file)

    @classmethod
    def save(cls, dest):
        """ Serialise the datacentre lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(cls.BLOBS, dest, cls=ObjectJsonEncoder)

    @classmethod
    def load(cls, src):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        cls.BLOBS.clear()
        cls.SIZE = 0
        cls.BLOBS = json.load(src, object_hook=Blob.json_decode)
        cls.update_sha1_lookup()

    @classmethod
    def check_and_create_root(cls, root_dir):
        """ Checks that the root dirs for the BlobStore exist and makes
        them if missing.
        """
        cls.ROOT = root_dir
        dirs = ['', cls.__blobpath__, cls.__metapath__]
        for directory in dirs:
            create_dirs(cls.ROOT + directory)

    @classmethod
    def reload_blobs(cls):
        """ Clears the lookup dictionary and loads the details of blob files
        from scratch.
        """
        cls.BLOBS.clear()
        blob_root = cls.ROOT + cls.__blobpath__
        for blob_name in only_files(blob_root):
            path = blob_root + blob_name
            byte_seq = ByteSequence(os.path.getsize(path), Sha1Lookup.get_sha1(blob_name))
            blob = Blob(blob_name, path, byte_seq)
            cls.BLOBS.update({blob_name : blob})

    @classmethod
    def get_format_info(cls):
        """Get the collections of format information"""
        return cls.FORMAT_INFO

def main():
    """
    Main method entry point, parses DOIs from Datacite and outputs to
    STDOUT.
    """
    Sha1Lookup.initialise()
    BlobStore.initialise(BLOB_STORE_ROOT, persist=True)
    print '{} blobs, {} bytes'.format(BlobStore.get_blob_count(), BlobStore.get_total_blob_size())
#    print "hash checking BLOB store"
#    blobstore.hash_check()

#    print "Running blobstore format identification"
#    blobstore.identify_contents()


if __name__ == "__main__":
    main()
