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
from datetime import datetime
import unittest

import dateutil.parser

from corptest.const import JISC_BUCKET
from corptest.model_sources import SCHEMES, ByteSequence, Source, FormatTool
from corptest.model_sources import SourceIndex, Key, DB_SESSION
from corptest.utilities import ObjectJsonEncoder
from corptest.format_tools import FormatToolRelease, get_format_tool_instance
from corptest.sources import FileSystem, SourceKey

from tests.const import THIS_DIR, TEST_DESCRIPTION, TEST_BUCKET_NAME
from tests.const import TEST_NAME, TEST_NAMESPACE
from tests.conf_test import db, session, app# pylint: disable-msg=W0611

TEST_ROOT = "__root__"
TEST_READABLE_ROOT = os.path.join(THIS_DIR, "disk-corpus")
TEST_BYTES_ROOT = os.path.join(THIS_DIR, "content-corpus")

class AS3BucketSourceTestCase(unittest.TestCase):
    """ Test cases for the AS3BucketSource class and methods. """
    def test_null_namespace(self):
        """ Test case for None name case. """
        with self.assertRaises(ValueError) as _:
            Source(None, TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_empty_namespace(self):
        """ Test case for empty name case. """
        with self.assertRaises(ValueError) as _:
            Source('', TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_null_name(self):
        """ Test case for None name case. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAMESPACE, None, TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_empty_name(self):
        """ Test case for empty name case. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAMESPACE, '', TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_null_description(self):
        """ Test case for None description case. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAMESPACE, TEST_NAME, None, SCHEMES['AS3'], TEST_BUCKET_NAME)

    def test_get_details(self):
        """ Test case for ensuring details threadthrough works. """
        bucket_source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                               SCHEMES['AS3'], TEST_BUCKET_NAME)
        self.assertEqual(bucket_source.name, TEST_NAME, \
        'bucket_source.name should equal test instance TEST_NAME')
        self.assertEqual(bucket_source.description, TEST_DESCRIPTION, \
        'bucket_source.details.description should equal test instance TEST__DESCT')

    def test_empty_bucket_name(self):
        """ Test case for empty name. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], '')

    def test_null_bucket_name(self):
        """ Test case for None name cases. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], None)

    def test_bucket_name(self):
        """ Test case for bucket name. """
        bucket_source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                               SCHEMES['AS3'], TEST_BUCKET_NAME)
        self.assertEqual(bucket_source.location, TEST_BUCKET_NAME, \
        'bucket_source.bucket_name should equal test instance TEST_BUCKET_NAME')
        bucket_source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                               SCHEMES['AS3'], JISC_BUCKET)
        self.assertEqual(bucket_source.location, JISC_BUCKET, \
        'bucket_source.bucket_name should equal test instance JISC_BUCKET')

def test_add_source(session):# pylint: disable-msg=W0621, W0613
    """Test Source model class persistence."""
    base_count = Source.count()
    bucket_source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                           SCHEMES['AS3'], TEST_BUCKET_NAME)
    Source.add(bucket_source)
    assert bucket_source.id > 0
    assert Source.count() == base_count + 1
    Source.add(bucket_source)
    assert Source.count() == base_count + 1
    retrieved_source = Source.by_name(TEST_NAME)
    assert bucket_source == retrieved_source
    bucket_by_id = Source.by_id(bucket_source.id)
    assert bucket_source == bucket_by_id
    bucket_by_namespace = Source.by_namespace_and_name(TEST_NAMESPACE, TEST_NAME)
    assert bucket_source == bucket_by_namespace
    source_by_scheme_count = len(Source.by_scheme(SCHEMES['AS3']))
    assert  source_by_scheme_count > 0
    for _source in Source.all():
        if _source.id == bucket_source.id:
            assert _source == bucket_source
        else:
            assert _source != bucket_source

class SourceIndexTestCase(unittest.TestCase):
    """ Test cases for the SourceIndex class and methods. """
    def test_null_source(self):
        """ Test case for None source case. """
        with self.assertRaises(ValueError) as _:
            SourceIndex(None)

    def test_get_timestamp(self):
        """ Test case for retrieveing timestamp. """
        _source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                         SCHEMES['AS3'], TEST_BUCKET_NAME)
        _source_index = SourceIndex(_source)
        self.assertTrue(_source_index.timestamp < datetime.now())

    def test_get_iso_timestamp(self):
        """ Test case for retrieveing timestamp. """
        _source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                         SCHEMES['AS3'], TEST_BUCKET_NAME)
        _timestamp = datetime.now()
        _source_index = SourceIndex(_source, _timestamp)
        self.assertEqual(_source_index.timestamp, _timestamp)
        _timestamp = dateutil.parser.parse(_source_index.iso_timestamp)
        self.assertEqual(_source_index.timestamp, _timestamp)

    def test_get_source(self):
        """ Test case for getting index sourdce. """
        _source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                         SCHEMES['AS3'], TEST_BUCKET_NAME)
        _source_index = SourceIndex(_source)
        self.assertEqual(_source_index.source, _source)

def test_source_index_add(session):# pylint: disable-msg=W0621, W0613
    """Test SourceIndex model class persistence."""
    index_count = SourceIndex.count()
    _source = Source.by_name(TEST_NAME)
    if not _source:
        _source = Source(TEST_NAMESPACE, TEST_NAME, TEST_DESCRIPTION,
                         SCHEMES['AS3'], TEST_BUCKET_NAME)
        _source.put()
    assert _source.id > 0
    _source_index = SourceIndex(_source)
    _source_index.put()
    assert _source_index.id > 0
    assert SourceIndex.count() > index_count
    _retrieved_index = SourceIndex.by_id(_source_index.id)
    assert _source_index == _retrieved_index
    _source = Source(TEST_NAMESPACE, TEST_NAME + " test",
                     TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)
    _source_index = SourceIndex(_source)
    _source_index.put()
    assert _source_index != _retrieved_index
    _index_count = len(SourceIndex.all())
    assert _index_count > 0

class KeyTestCase(unittest.TestCase):
    """ Test cases for the Key class and methods. """
    def setUp(self):
        """ Set up default instance """
        self.default_source = Source(TEST_NAMESPACE, TEST_NAME + " test",
                                     TEST_DESCRIPTION, SCHEMES['AS3'], TEST_BUCKET_NAME)
        self.def_index = SourceIndex(self.default_source)

    def test_null_source_index(self):
        """ Test case for None SourceIndex case. """
        with self.assertRaises(ValueError) as _:
            Key(None, 'test.dat', 1)

    def test_null_path(self):
        """ Test case for null path case. """
        with self.assertRaises(ValueError) as _:
            Key(self.def_index, None, 1)

    def test_empty_path(self):
        """ Test case for null path case. """
        with self.assertRaises(ValueError) as _:
            Key(self.def_index, '', 1)

    def test_null_size(self):
        """ Test case for null Size case. """
        with self.assertRaises(ValueError) as _:
            Key(self.def_index, 'test.dat', None)

    def test_less_than_zero(self):
        """ Test case for null Size case. """
        Key(self.def_index, 'test.dat', 0)
        with self.assertRaises(ValueError) as _:
            Key(self.def_index, 'test.dat', -1)

    def test_get_source_index(self):
        """ Test case for retrieving source index. """
        _key = Key(self.def_index, 'test.dat', 0)
        assert _key.source_index == self.def_index

def test_add_files(session):# pylint: disable-msg=W0621, W0613
    """ Set up default instance """
    corp_file_count = file_count(TEST_READABLE_ROOT)
    file_system_source = Source("test.readable", "Readable Test", TEST_DESCRIPTION, SCHEMES['FILE'],
                                TEST_READABLE_ROOT)
    file_system_index = SourceIndex(file_system_source, datetime.now())
    file_system_index.put()
    file_system = FileSystem(file_system_source)
    size_total_check = 0
    for key in file_system.all_file_keys():
        size_total_check += key.size
        _source_key = Key(file_system_index, key.value, key.size,
                          dateutil.parser.parse(key.last_modified))
        _source_key.put()
    DB_SESSION.commit()
    assert file_system_index.size == size_total_check
    assert file_system_index.key_count > 0
    assert Key.count() == corp_file_count
    by_index_id_count = len(Key.by_index_id(file_system_index.id))
    assert by_index_id_count == Key.count()
    for key in Key.all():
        file_key = SourceKey(key.path, False, key.size, key.last_modified)
        assert key.last_modified == dateutil.parser.parse(file_key.last_modified)
        retrieved_key = Key.by_id(key.id)
        assert retrieved_key == key

    file_system_index_two = SourceIndex(file_system_source, datetime.now())
    file_system_index_two.put()
    for key in file_system.all_file_keys():
        _source_key = Key(file_system_index_two, key.value, int(key.size),
                          dateutil.parser.parse(key.last_modified))
        _source_key.put()
        DB_SESSION.commit()
    assert Key.count() == (2 * corp_file_count)

def file_count(folder):
    "count the number of files in a directory"
    count = 0

    for filename in os.listdir(folder):
        path = os.path.join(folder, filename)

        if os.path.isfile(path):
            count += 1
        elif os.path.isdir(path):
            count += file_count(path)

    return count

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

def test_add_bytesequence(session):# pylint: disable-msg=W0621, W0613
    """ Set up default instance """
    corp_file_count = file_count(TEST_BYTES_ROOT)
    file_system_source = Source("bs.test", "BS Test", TEST_DESCRIPTION, SCHEMES['FILE'],
                                TEST_BYTES_ROOT)
    file_system_index = SourceIndex(file_system_source)
    file_system_index.put()
    file_system = FileSystem(file_system_source)
    for key in file_system.all_file_keys():
        assert key.size != 0
        _bs, _aug_key = file_system.get_byte_sequence_properties(key)
        assert _bs.sha1 != ByteSequence.EMPTY_SHA1
        _bytes = ByteSequence(_bs.sha1, int(key.size))
    _byte_count = len(ByteSequence.all())
    assert _byte_count == corp_file_count

def test_format_tool_release(session):# pylint: disable-msg=W0621, W0613
    """Test FormatToolRelease model class persistence."""
    tool_count = FormatTool.count()
    assert tool_count > 0
    tool_release_count = FormatToolRelease.count()
    assert tool_release_count > 0
    FormatToolRelease.all_unavailable()
    available_tools = len(FormatToolRelease.get_available())
    assert available_tools == 0
    FormatToolRelease.all_available()
    available_tools = len(FormatToolRelease.get_available())
    assert available_tools == tool_release_count
    for _tool in FormatTool.all():
        tool_release = get_format_tool_instance(_tool)
        if tool_release:
            assert tool_release.format_tool_release.id > 0
    for _tool in FormatToolRelease.all():
        _tool_check = FormatToolRelease.by_id(_tool.id)
        assert _tool == _tool_check
        _tool_check = FormatToolRelease.by_version(_tool.version)
        assert _tool == _tool_check
        _tool_check = FormatToolRelease.by_tool_and_version(_tool.format_tool, _tool.version)
        assert _tool == _tool_check
