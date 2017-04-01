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
import unittest
from corptest.blobstore import ByteSequence

class ByteSequenceTestCase(unittest.TestCase):
    def setUp(self):
        self.default_byte_seq = ByteSequence()

    def test_default_size(self):
        assert self.default_byte_seq.get_size() == 0, 'Default size should be zero'

    def test_default_sha1(self):
        assert self.default_byte_seq.get_sha1() == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
if __name__ == "__main__":
    unittest.main()
