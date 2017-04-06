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
#
""" Wrappers, serialisers and decoders for format identification tools. """
import collections

from const import RDSS_CACHE

MAGIC_DEFAULT = ''.join([RDSS_CACHE, 'magic-blobs.out'])
FILE_DEFAULT = ''.join([RDSS_CACHE, 'file-blobs.out'])
DROID_DEFAULT = ''.join([RDSS_CACHE, 'droid-blobs.out'])
TIKA_DEFAULT = ''.join([RDSS_CACHE, 'tika-blobs.out'])

class MagicLookup(object):
    """ Look up class for serialised file magic results. """
    def __init__(self, source_path=MAGIC_DEFAULT):
        self.source_path = source_path
        self.magic_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.magic_lookup)

    def get_magic_string(self, sha1):
        """ Retrieve and return a magic result by key. """
        return self.magic_lookup.get(sha1, None)

    @classmethod
    def load_from_file(cls, source_path=MAGIC_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        magic_lookup = collections.defaultdict(dict)
        for sha1, magic_string in file_by_line_split_generator(source_path):
            if not sha1 in magic_lookup:
                magic_lookup.update({sha1 : magic_string})
        return magic_lookup

class MimeLookup(object):
    """ Look up class for serialised file mime results. """
    def __init__(self, source_path=FILE_DEFAULT):
        self.source_path = source_path
        self.mime_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.mime_lookup)

    def get_mime_string(self, sha1):
        """ Retrieve and return MIME string by key. """
        return self.mime_lookup.get(sha1, None)

    @classmethod
    def load_from_file(cls, source_path=FILE_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        mime_lookup = collections.defaultdict(dict)
        for sha1, mime_string in file_by_line_split_generator(source_path):
            if not sha1 in mime_lookup:
                mime_lookup.update({sha1 : mime_string})
        return mime_lookup

class DroidLookup(object):
    """ Look up class for serialised droid results. """
    def __init__(self, source_path=DROID_DEFAULT):
        self.source_path = source_path
        self.puid_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.puid_lookup)

    def get_puid(self, key):
        """ Retrieve and return PUID string by key. """
        return self.puid_lookup.get(key, None)

    @classmethod
    def load_from_file(cls, source_path=DROID_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        puid_lookup = collections.defaultdict(dict)
        for sha1, puid in file_by_line_split_generator(source_path, ','):
            if not sha1 in puid_lookup:
                puid_lookup.update({sha1 : puid})
        return puid_lookup

class TikaLookup(object):
    """ Lookup class for Tika tika-ident pairs in serialised output. """
    def __init__(self, source_path=TIKA_DEFAULT):
        self.source_path = source_path
        self.mime_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.mime_lookup)

    def get_mime_string(self, sha1):
        """ Retrieve and return MIME string by key. """
        return self.mime_lookup.get(sha1, None)

    @classmethod
    def load_from_file(cls, source_path=TIKA_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        mime_lookup = collections.defaultdict(dict)
        for sha1, mime_string in file_by_line_split_generator(source_path):
            if not sha1 in mime_lookup:
                mime_lookup.update({sha1 : mime_string})
        return mime_lookup

def file_by_line_split_generator(path, splitter=':'):
    """ Convenience method to grab a file line by line. """
    with open(path) as src_file:
        for line in src_file:
            if splitter not in line:
                continue
            parts = line.split(splitter)
            yield get_sha1_from_path(parts[0].strip()), parts[1][:-1].strip()

def get_sha1_from_path(path_str):
    """ Parse the SHA1 from any BlobStore path. """
    return path_str.rpartition('/')[2]
