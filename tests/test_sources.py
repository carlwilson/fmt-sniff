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
from corptest.model import SourceDetails, SourceKey, AS3Bucket, FileSystem
from corptest.sources import AS3BucketSource, FileSystemSource
from tests.const import THIS_DIR

TEST_DETAILS = SourceDetails("Name", "Description")
TEST_BUCKET_NAME = "bucket"
TEST_ROOT = "__root__"
TEST_READABLE_ROOT = os.path.join(THIS_DIR, "disk-corpus")

class AS3BucketTestCase(unittest.TestCase):
    """ Test cases for the AS3Bucket class and methods. """
    def test_null_details(self):
        """ Test case for empty name cases. """
        with self.assertRaises(ValueError) as _:
            AS3Bucket(None, TEST_BUCKET_NAME)

    def test_get_details(self):
        """ Test case for ensuring details threadthrough works. """
        bucket = AS3Bucket(TEST_DETAILS, TEST_BUCKET_NAME)
        self.assertEqual(bucket.details.name, TEST_DETAILS.name, \
        'bucket_source.details.name should equal test instance TEST_DETAILS.name')
        self.assertEqual(bucket.details.description, TEST_DETAILS.description, \
        'bucket_source.details.description should equal test instance TEST_DETAILS.description')

    def test_empty_bucket_name(self):
        """ Test case for empty name. """
        with self.assertRaises(ValueError) as _:
            AS3Bucket(TEST_DETAILS, '')

    def test_null_bucket_name(self):
        """ Test case for empty name cases. """
        with self.assertRaises(ValueError) as _:
            AS3Bucket(TEST_DETAILS, None)

    def test_bucket_name(self):
        """ Test case for bucket name. """
        bucket = AS3Bucket(TEST_DETAILS, TEST_BUCKET_NAME)
        self.assertEqual(bucket.bucket_name, TEST_BUCKET_NAME, \
        'bucket_source.bucket_name should equal test instance TEST_BUCKET_NAME')
        bucket = AS3Bucket(TEST_DETAILS, JISC_BUCKET)
        self.assertEqual(bucket.bucket_name, JISC_BUCKET, \
        'bucket_source.bucket_name should equal test instance JISC_BUCKET')

class AS3BucketSourceTestCase(unittest.TestCase):
    """ Test cases for the AS3BucketSourceTestCase class and methods. """
    def test_bucket_name_not_exist(self):
        """ Test case for bucket name. """
        bucket = AS3Bucket(TEST_DETAILS, 'nosuchbucket')
        with self.assertRaises(ValueError) as _:
            AS3BucketSource(bucket)

    # @unittest.skip("Full get takes too long and is untestable")
    def test_list_all_keys(self):
        """ Test case for listing file system keys. """
        bucket = AS3Bucket(TEST_DETAILS, JISC_BUCKET)
        bucket_source = AS3BucketSource(bucket)
        count_keys = 0
        for _ in bucket_source.all_file_keys():
            count_keys += 1
        self.assertTrue(count_keys > 100000, '{} should be > 100000'.format(count_keys))

    def test_filter_folders(self):
        """ Test case for listing file system keys. """
        bucket = AS3Bucket(TEST_DETAILS, JISC_BUCKET)
        bucket_source = AS3BucketSource(bucket)
        count_root = 0
        for _ in bucket_source.list_folders():
            count_root += 1
        prefix = 'unsorted/'
        count_unsorted = 0
        listed_folders = set()
        for key in bucket_source.list_folders(filter_key=SourceKey(prefix)):
            count_unsorted += 1
            listed_folders.add(key)
        self.assertTrue(count_root < count_unsorted,
                        '{} should be < {}'.format(count_root, count_unsorted))
        self.assertTrue(SourceKey(os.path.join(prefix, '10.9774/')
                                 ) in listed_folders)
        self.assertTrue(SourceKey(os.path.join(prefix, '10.9753/')
                                 ) in listed_folders)
        self.assertFalse(SourceKey(os.path.join(prefix, 'GLEAF.2350.2014.00007',
                                                '10-9774-GLEAF-2350-2014-00007.json'),
                                   False) in listed_folders)

    def test_recurse_folders(self):
        """ Test case for listing file system keys. """
        bucket = AS3Bucket(TEST_DETAILS, JISC_BUCKET)
        bucket_source = AS3BucketSource(bucket)
        count_flat = 0
        filter_key = SourceKey("unsorted/10.9774/")
        for _ in bucket_source.list_folders(filter_key=filter_key):
            count_flat += 1
        count_recurse = 0
        listed_folders = set()
        for key in bucket_source.list_folders(filter_key=filter_key, recurse=True):
            count_recurse += 1
            listed_folders.add(key)
        self.assertTrue(count_recurse == count_flat,
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
        bucket = AS3Bucket(TEST_DETAILS, JISC_BUCKET)
        bucket_source = AS3BucketSource(bucket)
        count_flat = 0
        filter_key = SourceKey("unsorted/10.9774/")
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
        self.assertTrue(SourceKey(os.path.join("unsorted", '10.9774', 'GLEAF.2350.2014.00007',
                                               '10-9774-GLEAF-2350-2014-00007.json'),
                                  False) in listed_folders)

    def test_recurse_files(self):
        """Test filtering of files."""
        bucket = AS3Bucket(TEST_DETAILS, JISC_BUCKET)
        bucket_source = AS3BucketSource(bucket)
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

class FileSystemTestCase(unittest.TestCase):
    """ Test cases for the FileSystem class and methods. """
    def test_null_details(self):
        """ Test case for empty name cases. """
        with self.assertRaises(ValueError) as _:
            FileSystem(None, TEST_ROOT)

    def test_get_details(self):
        """ Test case for ensuring details threadthrough works. """
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        self.assertEqual(file_system.details.name, TEST_DETAILS.name, \
        'file_source.details.name should equal test instance TEST_DETAILS.name')
        self.assertEqual(file_system.details.description, TEST_DETAILS.description, \
        'file_source.details.description should equal test instance TEST_DETAILS.description')

    def test_empty_root(self):
        """ Test case for empty root. """
        with self.assertRaises(ValueError) as _:
            FileSystem(TEST_DETAILS, '')

    def test_null_root(self):
        """ Test case for null root case. """
        with self.assertRaises(ValueError) as _:
            FileSystem(TEST_DETAILS, None)

    def test_root(self):
        """ Test case for source root. """
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        self.assertEqual(file_system.root, TEST_READABLE_ROOT, \
        'bucket_source.details.name should equal test instance TEST_DETAILS.name')

class FileSystemSourceTestCase(unittest.TestCase):
    """Tests for FileSystemSource class."""
    def test_not_dir_root(self):
        """ Test case for not directory root case. """
        file_system = FileSystem(TEST_DETAILS, TEST_ROOT)
        with self.assertRaises(ValueError) as _:
            FileSystemSource(file_system)

    def test_list_file_keys(self):
        """ Test case for listing file system keys. """
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        file_source = FileSystemSource(file_system)
        listed_keys = set()
        for key in file_source.all_file_keys():
            listed_keys.add(key)
        self.assertTrue(len(listed_keys) == 8, '{} should be 8'.format(len(listed_keys)))
        self.assertFalse(SourceKey('folder-key-1') in listed_keys)
        self.assertFalse(SourceKey(os.path.join('folder-key-1', 'sub-folder-key-2')) in listed_keys)
        self.assertTrue(SourceKey(os.path.join('folder-key-1', 'file-key-1'), False) in listed_keys)

    def test_list_folders_file_key(self):
        """Test that passing a file filter throws a value error."""
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        file_source = FileSystemSource(file_system)
        with self.assertRaises(ValueError) as _:
            file_source.list_folders(filter_key=SourceKey("somekey", False))

    def test_list_folders(self):
        """ Test case for listing file system keys. """
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        file_source = FileSystemSource(file_system)
        listed_folders = []
        for key in file_source.list_folders(recurse=True):
            listed_folders.append(key)
        self.assertTrue(len(listed_folders) == 6, '{} should be 6'.format(len(listed_folders)))
        self.assertTrue(SourceKey(os.path.join('folder-key-2')) in listed_folders)
        self.assertTrue(SourceKey(os.path.join('folder-key-2',
                                               'sub-folder-key-1')) in listed_folders)
        self.assertFalse(SourceKey(os.path.join('folder-key-1',
                                                'file-key-1'), False) in listed_folders)

    def test_filter_folders(self):
        """ Test case for listing file system keys. """
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        file_source = FileSystemSource(file_system)
        listed_folders = []
        for key in file_source.list_folders(filter_key=SourceKey("folder-key-2"), recurse=True):
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
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        file_source = FileSystemSource(file_system)
        listed_files = set()
        for key in file_source.list_files(recurse=True):
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
        file_system = FileSystem(TEST_DETAILS, TEST_READABLE_ROOT)
        file_source = FileSystemSource(file_system)
        listed_files = set()
        for key in file_source.list_files(filter_key=SourceKey("folder-key-1"),
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
