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
""" Tests for the classes in blobstore.py. """
import os.path
import shutil
import tempfile
import unittest

from corptest.blobstore import ByteSequence, BlobStore
from corptest.utilities import ObjectJsonEncoder

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NOT_EMPTY_SHA1 = '0ae15d17576dc5a36ef2b933c303a1e214f57bee'

class ByteSequenceTestCase(unittest.TestCase):
    """ Test cases for the ByteSequence class and methods. """
    def setUp(self):
        """ Set up default instance """
        self.default_test = ByteSequence(ByteSequence.EMPTY_SHA1, 0)
        self.def_inst = ByteSequence.default_instance()

    def test_default_instance(self):
        """ Test case for default instance. """
        assert self.default_test == self.def_inst, \
        'Test default should be equal to default instance'

    def test_not_equal_non_bs(self):
        """ Test equality against non byte sequence object. """
        assert self.default_test != '', \
        'Test default instance should not equal to empty string'

    def test_from_empty_file(self):
        """ Test case for ByteSequence.from_file() method. """
        empty_test_path = os.path.join(THIS_DIR, 'empty')
        test_byte_seq = ByteSequence.from_file(empty_test_path)
        assert test_byte_seq == self.def_inst, \
        'Test from empty file should be equal to default instance'

    def test_from_file(self):
        """ Test case for ByteSequence.from_file() method. """
        notempty_test_path = os.path.join(THIS_DIR, 'notempty')
        test_byte_seq = ByteSequence.from_file(notempty_test_path)
        assert test_byte_seq != self.def_inst, \
        'Test from file should NOT be equal to default instance'

    def test_from_file_no_file(self):
        """ Test case for ByteSequence.from_file() method with nonexistent file. """
        notempty_test_path = os.path.join(THIS_DIR, 'notexist')
        with self.assertRaises(IOError) as context:
            test_byte_seq = ByteSequence.from_file(notempty_test_path)

    def test_from_empty_string(self):
        """ Test case for ByteSequence.from_string() method. """
        test_byte_seq = ByteSequence.from_string('')
        assert test_byte_seq == self.def_inst, \
        'Test from empty file should be equal to default instance'

    def test_from_string(self):
        """ Test case for ByteSequence.from_string() method. """
        test_byte_seq = ByteSequence.from_string('notempty')
        assert test_byte_seq != self.def_inst, \
        'Test from file should NOT be equal to default instance'

    def test_json_empty(self):
        """ Test case for ByteSequence.json_decode() method. """
        encoder = ObjectJsonEncoder()
        json_string = encoder.default(self.def_inst)
        test_byte_seq = ByteSequence.json_decode(json_string)
        assert test_byte_seq == self.def_inst, \
        'Test from JSON should be equal to default instance'

    def test_json_not_empty(self):
        """ Test case for ByteSequence.json_decode() method. """
        encoder = ObjectJsonEncoder()
        notempty_test_path = os.path.join(THIS_DIR, 'notempty')
        byte_seq = ByteSequence.from_file(notempty_test_path)
        json_string = encoder.default(byte_seq)
        test_byte_seq = ByteSequence.json_decode(json_string)
        assert test_byte_seq != self.def_inst, \
        'Test from JSON should be equal to default instance'

class BlobStoreTestCase(unittest.TestCase):
    """ Test cases for the BlobStore class and methods. """
    def setUp(self):
        """ Sets up a BlobStore in a temp directory. """
        self.tmp_store = tempfile.mkdtemp()
        self.blobstore = BlobStore(self.tmp_store)

    def test_empty_store(self):
        """ Test for empty store properties. """
        self.blobstore.clear()
        assert self.blobstore.get_blob_count() == 0, \
        'Empty BlobStore should have blob count 0'
        assert self.blobstore.get_size() == 0, \
        'Empty BlobStore should have size 0'
        assert self.blobstore.get_root() == self.tmp_store, \
        'Empty BlobStore should have root same as tmp_store'

    def test_add_item(self):
        """ Test for empty store properties adding item works properly. """
        self.blobstore.clear()
        assert self.blobstore.get_blob_count() == 0, \
        'Reset BlobStore should have blob count 0'
        self.store_file('empty')
        byte_seq = ByteSequence.default_instance()
        assert self.blobstore.get_blob_count() == 1, \
        'BlobStore should contain a single item'
        assert byte_seq.get_size() == 0, \
        'Returned ByteSequence should have size 0'
        assert byte_seq.get_sha1() == ByteSequence.EMPTY_SHA1, \
        'Returned ByteSequence should have null stream SHA1 value'

    def test_add_item_with_hash(self):
        """ Test for empty store properties adding item works properly. """
        self.blobstore.clear()
        assert self.blobstore.get_blob_count() == 0, \
        'Reset BlobStore should have blob count 0'
        empty_test_path = os.path.join(THIS_DIR, 'empty')
        byte_seq = self.blobstore.add_file(empty_test_path, ByteSequence.EMPTY_SHA1)
        assert byte_seq.get_size() == 0, \
        'Returned ByteSequence should have size 0'
        assert byte_seq.get_sha1() == ByteSequence.EMPTY_SHA1, \
        'Returned ByteSequence should have null stream SHA1 value'

    def test_add_item_bad_hash(self):
        """ Test to ensure adding item with an inconsistent SHA1 raises an IOError """
        self.blobstore.clear()
        assert self.blobstore.get_blob_count() == 0, \
        'Reset BlobStore should have blob count 0'
        notempty_test_path = os.path.join(THIS_DIR, 'notempty')
        with self.assertRaises(IOError) as context:
            self.blobstore.add_file(notempty_test_path, ByteSequence.EMPTY_SHA1)

    def test_get_item(self):
        """ Test that blob retrieval from store works as expected. """
        self.populate_and_assert_blobstore()
        byte_sequence = self.blobstore.get_blob(ByteSequence.EMPTY_SHA1)
        assert byte_sequence == ByteSequence.default_instance(), \
        'Retrieved ByteSequence should equal default empty sequence'
        byte_sequence = self.blobstore.get_blob(NOT_EMPTY_SHA1)
        assert byte_sequence.get_sha1() == NOT_EMPTY_SHA1, \
        'Retrieved ByteSequence should equal notempty sequence'

    def test_clear(self):
        """ Test than clear emptys the blobstore. """
        self.populate_and_assert_blobstore()
        self.blobstore.clear()
        assert self.blobstore.get_blob_count() == 0, \
        'Empty BlobStore should have blob count 0'
        assert self.blobstore.get_size() == 0, \
        'Empty BlobStore should have size 0'

    def test_hash_check(self):
        """ Test for hash checking the blob store. """
        self.populate_and_assert_blobstore()
        self.assertTrue(self.blobstore.hash_check(),
                        'Consistent BlobStore should hash_check True')
        src = os.path.join(THIS_DIR, 'notempty')
        shutil.copyfile(src, self.blobstore.get_blob_path(ByteSequence.EMPTY_SHA1))
        self.assertFalse(self.blobstore.hash_check(),
                        'Inconsistent BlobStore should hash_check False')

    def test_reload_blobs(self):
        """ Test reload blobs functions as expected. """
        self.populate_and_assert_blobstore()
        prev_count = self.blobstore.get_blob_count()
        prev_size = self.blobstore.get_size()
        self.blobstore.reload_blobs()
        assert self.blobstore.get_blob_count() == prev_count
        assert self.blobstore.get_size() == prev_size

    def store_file(self, filename):
        path = os.path.join(THIS_DIR, filename)
        self.blobstore.add_file(path)

    def tearDown(self):
        """ Remove the BlobStore's temp directory. """
        shutil.rmtree(self.tmp_store)

    def populate_and_assert_blobstore(self):
        """ Test reload blobs functions as expected. """
        self.store_file('empty')
        self.store_file('notempty')
        assert self.blobstore.get_blob_count() > 0, \
        'BlobStore should have blob count > 0'
        assert self.blobstore.get_size() > 0, \
        'BlobStore should have size > 0'

if __name__ == "__main__":
    unittest.main()
