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
""" Tests for the classes in sources.py. """
import os.path
import unittest

from corptest.const import JISC_BUCKET
from corptest.model import SCHEMES, Source
from corptest.sources import SourceKey, AS3Bucket, FileSystem
from tests.const import THIS_DIR, TEST_DESCRIPTION, TEST_NAME

TEST_ROOT = "__root__"
TEST_READABLE_ROOT = os.path.join(THIS_DIR, "disk-corpus")

class SourceKeyTestCase(unittest.TestCase):
    """ Test cases for the SourceDetails class and methods. """
    # def test_empty_value(self):
    #     """ Test case for empty value. """
    #     with self.assertRaises(ValueError) as _:
    #         SourceKey('')
    #
    def test_null_value(self):
        """ Test case for null value."""
        with self.assertRaises(ValueError) as _:
            SourceKey(None, 'Description')

    def test_ne_other_type(self):
        """Test that not equal to other type."""
        self.assertTrue(SourceKey('key') != "key")

class AS3BucketTestCase(unittest.TestCase):
    """ Test cases for the AS3BucketTestCase class and methods. """
    def test_bucket_name_not_exist(self):
        """ Test case for bucket name. """
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], 'nokjhsdfhsuchbucket')
        with self.assertRaises(ValueError) as _:
            AS3Bucket(bucket_source)

    def test_filter_folders(self):
        """ Test case for listing file system keys. """
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], JISC_BUCKET)
        bucket = AS3Bucket(bucket_source)
        count_root = 0
        for _ in bucket.list_folders():
            count_root += 1
        prefix = 'unsorted/'
        count_unsorted = 0
        listed_folders = set()
        for key in bucket.list_folders(filter_key=SourceKey(prefix)):
            count_unsorted += 1
            listed_folders.add(key)
        self.assertTrue(count_root < count_unsorted,
                        '{} should be < {}'.format(count_root, count_unsorted))
        self.assertTrue(SourceKey(os.path.join(prefix, '10.9774/')
                                 ) in listed_folders)
        self.assertTrue(SourceKey(os.path.join(prefix, '10.9734/')
                                 ) in listed_folders)
        self.assertFalse(SourceKey(os.path.join(prefix, 'GLEAF.2350.2014.00007',
                                                '10-9774-GLEAF-2350-2014-00007.json'),
                                   False) in listed_folders)

    def test_recurse_folders(self):
        """ Test case for listing file system keys. """
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], JISC_BUCKET)
        bucket = AS3Bucket(bucket_source)
        count_flat = 0
        filter_key = SourceKey("unsorted/10.9774/")
        for _ in bucket.list_folders(filter_key=filter_key):
            count_flat += 1
        count_recurse = 0
        listed_folders = set()
        for key in bucket.list_folders(filter_key=filter_key, recurse=True):
            count_recurse += 1
            listed_folders.add(key)
        self.assertTrue(count_recurse >= count_flat,
                        '{} should be == {}'.format(count_recurse, count_flat))
        self.assertTrue(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.00007/')
                                 ) in listed_folders)
        self.assertTrue(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.no.00006/')
                                 ) in listed_folders)
        self.assertFalse(SourceKey(os.path.join("unsorted", 'GLEAF.2350.2014.00007',
                                                '10-9774-GLEAF-2350-2014-00007.json'),
                                   False) in listed_folders)

    def test_filter_files(self):
        """Test filtering of files."""
        bucket_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], JISC_BUCKET)
        bucket = AS3Bucket(bucket_source)
        count_flat = 0
        filter_key = SourceKey("unsorted/10.9774/")
        for _ in bucket.list_files(filter_key=filter_key):
            count_flat += 1
        count_recurse = 0
        listed_folders = set()
        for key in bucket.list_files(filter_key=filter_key, recurse=True):
            count_recurse += 1
            listed_folders.add(key)
        self.assertTrue(count_recurse > count_flat,
                        '{} should be > {}'.format(count_recurse, count_flat))
        self.assertFalse(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.00007/')
                                  ) in listed_folders)
        self.assertFalse(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.no.00006/')
                                  ) in listed_folders)
        self.assertTrue(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.00007',
                                               '10-9774-GLEAF-2350-2014-00007.json'),
                                  False) in listed_folders)

    def test_recurse_files(self):
        """Test filtering of files."""
        bucket = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['AS3'], JISC_BUCKET)
        bucket_source = AS3Bucket(bucket)
        count_flat = 0
        filter_key = SourceKey("unsorted/10.17863/")
        for _ in bucket_source.list_files(filter_key=filter_key):
            count_flat += 1
        count_recurse = 0
        listed_folders = set()
        for key in bucket_source.list_files(filter_key=filter_key, recurse=True):
            count_recurse += 1
            listed_folders.add(key)
        self.assertTrue(count_recurse > count_flat,
                        '{} should be > {}'.format(count_recurse, count_flat))
        self.assertFalse(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.00007/')
                                  ) in listed_folders)
        self.assertFalse(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.no.00006/')
                                  ) in listed_folders)
        self.assertTrue(SourceKey(os.path.join("unsorted", "10.17863", 'CAM.703',
                                               'ff-t5k-jses.tar.gz'),
                                  False) in listed_folders)

class SourceTestCase(unittest.TestCase):
    """ Test cases for the FileSystem class and methods. """
    def test_null_name(self):
        """ Test case for None name case. """
        with self.assertRaises(ValueError) as _:
            Source(None, TEST_DESCRIPTION, SCHEMES['FILE'], TEST_ROOT)

    def test_empty_name(self):
        """ Test case for empty name case. """
        with self.assertRaises(ValueError) as _:
            Source('', TEST_DESCRIPTION, SCHEMES['FILE'], TEST_ROOT)

    def test_null_description(self):
        """ Test case for None description case. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAME, None, SCHEMES['FILE'], TEST_ROOT)

    def test_get_details(self):
        """ Test case for ensuring details threadthrough works. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        self.assertEqual(file_system_source.name, TEST_NAME, \
        'file_source.details.name should equal TEST_NAME')
        self.assertEqual(file_system_source.description, TEST_DESCRIPTION, \
        'file_source.details.description should equal TEST_DESCRIPTION')

    def test_empty_root(self):
        """ Test case for empty root. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'], '')

    def test_null_root(self):
        """ Test case for null root case. """
        with self.assertRaises(ValueError) as _:
            Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'], None)

    def test_root(self):
        """ Test case for source root. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        self.assertEqual(file_system_source.location, TEST_READABLE_ROOT, \
        'file_system_source.root should equal test instance TEST_READABLE_ROOT')

class FileSystemTestCase(unittest.TestCase):
    """Tests for Source class."""
    def test_not_dir_root(self):
        """ Test case for not directory root case. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'], TEST_ROOT)
        with self.assertRaises(ValueError) as _:
            FileSystem(file_system_source)

    def test_list_file_keys(self):
        """ Test case for listing file system keys. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        file_system = FileSystem(file_system_source)
        listed_keys = set()
        for key in file_system.all_file_keys():
            listed_keys.add(key)
        self.assertTrue(len(listed_keys) == 8, '{} should be 8'.format(len(listed_keys)))
        self.assertFalse(SourceKey('folder-key-1') in listed_keys)
        self.assertFalse(SourceKey(os.path.join('folder-key-1', 'sub-folder-key-2')) in listed_keys)
        self.assertTrue(SourceKey(os.path.join('folder-key-1', 'file-key-1'), False) in listed_keys)

    def test_list_folders_file_key(self):
        """Test that passing a file filter throws a value error."""
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        file_system = FileSystem(file_system_source)
        with self.assertRaises(ValueError) as _:
            file_system.list_folders(filter_key=SourceKey("somekey", False))

    def test_list_folders(self):
        """ Test case for listing file system keys. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        file_system = FileSystem(file_system_source)
        listed_folders = []
        for key in file_system.list_folders(recurse=True):
            listed_folders.append(key)
        self.assertTrue(len(listed_folders) == 6, '{} should be 6'.format(len(listed_folders)))
        self.assertTrue(SourceKey(os.path.join('folder-key-2')) in listed_folders)
        self.assertTrue(SourceKey(os.path.join('folder-key-2',
                                               'sub-folder-key-1')) in listed_folders)
        self.assertFalse(SourceKey(os.path.join('folder-key-1',
                                                'file-key-1'), False) in listed_folders)

    def test_filter_folders(self):
        """ Test case for listing file system keys. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        file_system = FileSystem(file_system_source)
        listed_folders = []
        for key in file_system.list_folders(filter_key=SourceKey("folder-key-2"), recurse=True):
            listed_folders.append(key)
        self.assertTrue(len(listed_folders) == 2, '{} should be 2'.format(len(listed_folders)))
        self.assertFalse(SourceKey(os.path.join('folder-key-2')) in listed_folders)
        self.assertTrue(SourceKey(os.path.join('folder-key-2',
                                               'sub-folder-key-1')) in listed_folders)
        self.assertTrue(SourceKey(os.path.join('folder-key-2',
                                               'sub-folder-key-2')) in listed_folders)
        self.assertFalse(SourceKey(os.path.join('folder-key-2',
                                                'file-key-1'), False) in listed_folders)

    def test_list_files(self):
        """ Test case for listing file system keys. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        file_system = FileSystem(file_system_source)
        listed_files = set()
        for key in file_system.list_files(recurse=True):
            listed_files.add(key)
        self.assertTrue(len(listed_files) == 8, '{} should be 8'.format(len(listed_files)))
        self.assertFalse(SourceKey(os.path.join('folder-key-2')) in listed_files)
        self.assertFalse(SourceKey(os.path.join('folder-key-2',
                                                'sub-folder-key-1')) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1',
                                               'file-key-1'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1',
                                               'file-key-2'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1', 'sub-folder-key-1',
                                               'file-key-1'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1', 'sub-folder-key-2',
                                               'file-key-2'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-2',
                                               'file-key-1'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-2',
                                               'file-key-2'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-2', 'sub-folder-key-1',
                                               'file-key-2'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-2', 'sub-folder-key-2',
                                               'file-key-1'), False) in listed_files)

    def test_filter_files(self):
        """ Test case for listing file system keys. """
        file_system_source = Source(TEST_NAME, TEST_DESCRIPTION, SCHEMES['FILE'],
                                    TEST_READABLE_ROOT)
        file_system = FileSystem(file_system_source)
        listed_files = set()
        for key in file_system.list_files(filter_key=SourceKey("folder-key-1"),
                                          recurse=True):
            listed_files.add(key)
        self.assertTrue(len(listed_files) == 4, '{} should be 4'.format(len(listed_files)))
        self.assertFalse(SourceKey('folder-key-1') in listed_files)
        self.assertFalse(SourceKey(os.path.join('folder-key-1',
                                                'sub-folder-key-1')) in listed_files)
        self.assertFalse(SourceKey(os.path.join('folder-key-2',
                                                'file-key-1'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1',
                                               'file-key-1'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1',
                                               'file-key-2'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1', 'sub-folder-key-1',
                                               'file-key-1'), False) in listed_files)
        self.assertTrue(SourceKey(os.path.join('folder-key-1', 'sub-folder-key-2',
                                               'file-key-2'), False) in listed_files)
