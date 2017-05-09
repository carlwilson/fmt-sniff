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
""" Tests for the classes in model.py. """
import os.path
import unittest

from corptest.const import JISC_BUCKET
from corptest.model import ByteSequence, AS3BucketSource
from corptest.utilities import ObjectJsonEncoder

from tests.const import THIS_DIR, TEST_DESCRIPTION, TEST_NAME, TEST_BUCKET_NAME

class AS3BucketSourceTestCase(unittest.TestCase):
    """ Test cases for the AS3BucketSource class and methods. """
    def test_null_name(self):
        """ Test case for None name case. """
        with self.assertRaises(ValueError) as _:
            AS3BucketSource(None, TEST_DESCRIPTION, TEST_BUCKET_NAME)

    def test_empty_name(self):
        """ Test case for empty name case. """
        with self.assertRaises(ValueError) as _:
            AS3BucketSource('', TEST_DESCRIPTION, TEST_BUCKET_NAME)

    def test_null_description(self):
        """ Test case for None description case. """
        with self.assertRaises(ValueError) as _:
            AS3BucketSource(TEST_NAME, None, TEST_BUCKET_NAME)

    def test_get_details(self):
        """ Test case for ensuring details threadthrough works. """
        bucket_source = AS3BucketSource(TEST_NAME, TEST_DESCRIPTION, TEST_BUCKET_NAME)
        self.assertEqual(bucket_source.name, TEST_NAME, \
        'bucket_source.name should equal test instance TEST_NAME')
        self.assertEqual(bucket_source.description, TEST_DESCRIPTION, \
        'bucket_source.details.description should equal test instance TEST__DESCT')

    def test_empty_bucket_name(self):
        """ Test case for empty name. """
        with self.assertRaises(ValueError) as _:
            AS3BucketSource(TEST_NAME, TEST_DESCRIPTION, '')

    def test_null_bucket_name(self):
        """ Test case for None name cases. """
        with self.assertRaises(ValueError) as _:
            AS3BucketSource(TEST_NAME, TEST_DESCRIPTION, None)

    def test_bucket_name(self):
        """ Test case for bucket name. """
        bucket_source = AS3BucketSource(TEST_NAME, TEST_DESCRIPTION, TEST_BUCKET_NAME)
        self.assertEqual(bucket_source.bucket_name, TEST_BUCKET_NAME, \
        'bucket_source.bucket_name should equal test instance TEST_BUCKET_NAME')
        bucket_source = AS3BucketSource(TEST_NAME, TEST_DESCRIPTION, JISC_BUCKET)
        self.assertEqual(bucket_source.bucket_name, JISC_BUCKET, \
        'bucket_source.bucket_name should equal test instance JISC_BUCKET')

class ByteSequenceTestCase(unittest.TestCase):
    """ Test cases for the ByteSequence class and methods. """
    def setUp(self):
        """ Set up default instance """
        self.default_test = ByteSequence(ByteSequence.EMPTY_SHA1, 0)
        self.def_inst = ByteSequence.default_instance()

    def test_default_instance(self):
        """ Test case for default instance. """
        self.assertEqual(self.default_test, self.def_inst,
                         'Test default should be equal to default instance')

    def test_not_equal_non_bs(self):
        """ Test equality against non byte sequence object. """
        self.assertNotEqual(self.default_test, '',
                            'Test default instance should not equal to empty string')

    def test_from_empty_file(self):
        """ Test case for ByteSequence.from_file() method. """
        empty_test_path = os.path.join(THIS_DIR, 'empty')
        test_byte_seq = ByteSequence.from_file(empty_test_path)
        self.assertEqual(test_byte_seq, self.def_inst,
                         'Test from empty file should be equal to default instance')

    def test_from_file(self):
        """ Test case for ByteSequence.from_file() method. """
        notempty_test_path = os.path.join(THIS_DIR, 'notempty')
        test_byte_seq = ByteSequence.from_file(notempty_test_path)
        self.assertNotEqual(test_byte_seq, self.def_inst,
                            'Test from file should NOT be equal to default instance')

    def test_from_file_no_file(self):
        """ Test case for ByteSequence.from_file() method with nonexistent file. """
        notempty_test_path = os.path.join(THIS_DIR, 'notexist')
        with self.assertRaises(IOError) as _:
            ByteSequence.from_file(notempty_test_path)

    def test_from_empty_string(self):
        """ Test case for ByteSequence.from_string() method. """
        test_byte_seq = ByteSequence.from_string('')
        self.assertEqual(test_byte_seq, self.def_inst,
                         'Test from empty file should be equal to default instance')

    def test_from_string(self):
        """ Test case for ByteSequence.from_string() method. """
        test_byte_seq = ByteSequence.from_string('notempty')
        self.assertNotEqual(test_byte_seq, self.def_inst,
                            'Test from file should NOT be equal to default instance')

    def test_json_empty(self):
        """ Test case for ByteSequence.json_decode() method. """
        encoder = ObjectJsonEncoder()
        json_string = encoder.default(self.def_inst)
        test_byte_seq = ByteSequence.json_decode(json_string)
        self.assertEqual(test_byte_seq, self.def_inst,
                         'Test from JSON should be equal to default instance')

    def test_json_not_empty(self):
        """ Test case for ByteSequence.json_decode() method. """
        encoder = ObjectJsonEncoder()
        notempty_test_path = os.path.join(THIS_DIR, 'notempty')
        byte_seq = ByteSequence.from_file(notempty_test_path)
        json_string = encoder.default(byte_seq)
        test_byte_seq = ByteSequence.json_decode(json_string)
        self.assertNotEqual(test_byte_seq, self.def_inst,
                            'Test from JSON should be equal to default instance')
