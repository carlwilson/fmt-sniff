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

from corptest.model import SourceDetails, SourceKey, ByteSequence
from corptest.utilities import ObjectJsonEncoder

from tests.const import THIS_DIR

TEST_DETAILS = SourceDetails("Name", "Description")

class SourceDetailsTestCase(unittest.TestCase):
    """ Test cases for the SourceDetails class and methods. """
    def test_empty_name(self):
        """ Test case for empty name. """
        with self.assertRaises(ValueError) as _:
            SourceDetails('', 'Description')

    def test_null_name(self):
        """ Test case for empty name cases. """
        with self.assertRaises(ValueError) as _:
            SourceDetails(None, 'Description')

class SourceKeyTestCase(unittest.TestCase):
    """ Test cases for the SourceDetails class and methods. """
    def test_empty_value(self):
        """ Test case for empty value. """
        with self.assertRaises(ValueError) as _:
            SourceKey('')

    def test_null_value(self):
        """ Test case for null value."""
        with self.assertRaises(ValueError) as _:
            SourceKey(None, 'Description')

    def test_ne_other_type(self):
        """Test that not equal to other type."""
        self.assertTrue(SourceKey('key') != "key")

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
        with self.assertRaises(IOError) as _:
            ByteSequence.from_file(notempty_test_path)

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
