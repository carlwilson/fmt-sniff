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
""" Tests for the classes in corpora.py. """
import os
import unittest

from corptest.blobstore import ByteSequence
from corptest.corpora import CorpusItem
from corptest.utilities import ObjectJsonEncoder

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

class CorpusItemTestCase(unittest.TestCase):
    """ Tests for the CorpusItem class. """
    def test_from_file(self):
        """ Test creation of CorpusItem from a file. """
        empty_test_path = os.path.join(THIS_DIR, 'empty')
        corpus_item = CorpusItem.from_file(empty_test_path)
        assert corpus_item.get_path() == empty_test_path, \
        'item path should equal empty test path'
        assert corpus_item.get_size() == 0, \
        'item size should be zero'
        assert corpus_item.get_sha1() == ByteSequence.EMPTY_SHA1, \
        'item sha1 should be null string sha1'

    def test_from_file_no_file(self):
        """ Test case for CorpusItem.from_file() method with nonexistent file. """
        notempty_test_path = os.path.join(THIS_DIR, 'notexist')
        with self.assertRaises(IOError) as context:
            CorpusItem.from_file(notempty_test_path)

    def test_json_empty(self):
        """ Test case for ByteSequence.json_decode() method. """
        encoder = ObjectJsonEncoder()
        empty_test_path = os.path.join(THIS_DIR, 'empty')
        empty_item = CorpusItem.from_file(empty_test_path)
        json_string = encoder.default(empty_item)
        test_item = CorpusItem.json_decode(json_string)
        assert test_item == empty_item, \
        'Test from JSON should be equal to default instance'

    def test_json_not_empty(self):
        """ Test case for ByteSequence.json_decode() method. """
        encoder = ObjectJsonEncoder()
        notempty_test_path = os.path.join(THIS_DIR, 'notempty')
        not_empty_item = CorpusItem.from_file(notempty_test_path)
        json_string = encoder.default(not_empty_item)
        test_item = CorpusItem.json_decode(json_string)
        assert test_item == not_empty_item, \
        'Test from JSON should be equal to not_empty_item'
