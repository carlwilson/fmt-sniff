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
from corptest.model import SCHEMES, ByteSequence, Source, FormatTool
from corptest.utilities import ObjectJsonEncoder
from corptest.format_tools import FormatToolRelease, get_format_tool_instance

from tests.const import THIS_DIR, TEST_DESCRIPTION, TEST_NAME, TEST_BUCKET_NAME
from tests.conf_test import db, session, app

class AS3BucketSourceTestCase(unittest.TestCase):
    """ Test cases for the AS3BucketSource class and methods. """
    def test_null_name(self):
        """ Test case for None name case. """
        with self.assertRaises(ValueError) as _:
            Source(None, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_empty_name(self):
        """ Test case for empty name case. """
        with self.assertRaises(ValueError) as _:
            Source('', TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_null_description(self):
        """ Test case for None description case. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAME, None, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_get_details(self):
        """ Test case for ensuring details threadthrough works. """
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)
        self.assertEqual(bucket_source.name, TEST_NAME, \
        'bucket_source.name should equal test instance TEST_NAME')
        self.assertEqual(bucket_source.description, TEST_DESCRIPTION, \
        'bucket_source.details.description should equal test instance TEST__DESCT')

    def test_empty_bucket_name(self):
        """ Test case for empty name. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], '')

    def test_null_bucket_name(self):
        """ Test case for None name cases. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], None)

    def test_bucket_name(self):
        """ Test case for bucket name. """
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)
        self.assertEqual(bucket_source.location, TEST_BUCKET_NAME, \
        'bucket_source.bucket_name should equal test instance TEST_BUCKET_NAME')
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], JISC_BUCKET)
        self.assertEqual(bucket_source.location, JISC_BUCKET, \
        'bucket_source.bucket_name should equal test instance JISC_BUCKET')

def test_add_source(session):
    base_count = Source.count()
    bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)
    Source.add(bucket_source)
    id_value = bucket_source.id
    assert bucket_source.id > 0
    assert Source.count() == base_count + 1
    Source.add(bucket_source)
    assert Source.count() == base_count + 1
    retrieved_source = Source.by_name(TEST_NAME)
    assert bucket_source == retrieved_source
    retrieved_source = Source.by_id(id_value)
    assert bucket_source == retrieved_source
    for _source in Source.all():
        if _source.id == bucket_source.id:
            assert _source == bucket_source
        else:
            assert _source != bucket_source

def test_format_tool_release(session):
    tool_count = FormatToolRelease.count();
    for _tool in FormatTool.all():
        tool_release = get_format_tool_instance(_tool)
        if tool_release:
            tool_release.putdate()
    assert tool_count == FormatToolRelease.count()

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
