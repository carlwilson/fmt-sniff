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
""" Tests for the classes in format_tools.py. """

import os
import unittest

from corptest.format_tools import _get_sha1_from_path, MimeLookup, DroidLookup, TikaLookup
from tests.const import THIS_DIR

TEST_SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
LONG_MIME =\
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=binary'
class MimeLookupTestCase(unittest.TestCase):
    """ Tests for the MagicLookup class. """
    def test_sha1_from_path(self):
        """ Tests for simple sha1 from path method. """
        self.assertEqual(TEST_SHA1, _get_sha1_from_path(TEST_SHA1))
        self.assertEqual(TEST_SHA1, _get_sha1_from_path('/' + TEST_SHA1))
        self.assertEqual(TEST_SHA1, _get_sha1_from_path('/test/' + TEST_SHA1))

    def test_mime_lookup(self):
        """ Test for the MIME lookup class for file data. """
        mime_out_test_path = os.path.join(THIS_DIR, 'file-blobs.out')
        mime_lookup = MimeLookup(mime_out_test_path)
        self.assertEqual(mime_lookup.get_entry_count(), 5)
        self.assertEqual(mime_lookup.get_mime_string('4b11cb448cab68470c546bc52220b01fbc4572f7'),
                         'image/png; charset=binary')
        self.assertEqual(mime_lookup.get_mime_string('f8fa2aa81a623f9847436c5162d4e775e04cd948'),
                         'text/plain; charset=us-ascii')
        self.assertEqual(mime_lookup.get_mime_string('9f422292259b59ee6c9ad7a25180b0afc16f47e9'),
                         LONG_MIME)
        self.assertEqual(mime_lookup.get_mime_string('d1717e616fdae20110acb51b3ba3a37350628131'),
                         'application/pdf; charset=binary')
        self.assertEqual(mime_lookup.get_mime_string('a7510ac5483396687bf670860f48d21eecede68a'),
                         'application/zip; charset=binary')

class DroidLookupTestCase(unittest.TestCase):
    """ Tests for the DroidLookup class. """
    def test_droid_lookup(self):
        """ Test for the DROID lookup class for file data. """
        droid_out_test_path = os.path.join(THIS_DIR, 'droid-blobs.out')
        droid_lookup = DroidLookup(droid_out_test_path)
        self.assertEqual(droid_lookup.get_entry_count(), 5)
        self.assertEqual(droid_lookup.get_puid('2806d9cd6666d6aae3934e87905fc3291c4b1693'),
                         'Unknown')
        self.assertEqual(droid_lookup.get_puid('3f4a7df345d3ccdf8bf5a6e78d1d3c59d3641772'),
                         'fmt/18')
        self.assertEqual(droid_lookup.get_puid('c37672e0ba9afef20d4f053da5c68621ed6bb507'),
                         'fmt/11')
        self.assertEqual(droid_lookup.get_puid('a2dc22c72b9a615e2114000572ea217c8e36e382'),
                         'fmt/19')
        self.assertEqual(droid_lookup.get_puid('5d2fa9ef4448099821f0a56d29c9017d50b63f7e'),
                         'fmt/19')

class TikaLookupTestCase(unittest.TestCase):
    """ Tests for the TikaLookup class. """
    def test_droid_lookup(self):
        """ Test for the DROID lookup class for file data. """
        tika_out_test_path = os.path.join(THIS_DIR, 'tika-blobs.out')
        tika_lookup = TikaLookup(tika_out_test_path)
        self.assertEqual(tika_lookup.get_entry_count(), 4)
        self.assertEqual(tika_lookup.mime_lookup.get('4389b9a6306643ed0bd79db4e781179ab022f25b'),
                         'text/plain')
        self.assertEqual(tika_lookup.get_mime_string('984b6966cbd68188f9507cbb3a39971270210ee5'),
                         'application/pdf')
        self.assertEqual(tika_lookup.get_mime_string('09f311d38aa01e439de31f07093a12b6616d2e06'),
                         'application/x-tika-ooxml')
        self.assertEqual(tika_lookup.get_mime_string('a00628c26d71c6ca95c67327bb56cf680699e26a'),
                         'application/x-tika-msoffice')
