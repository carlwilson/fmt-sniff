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
#
""" Wrappers, serialisers and decoders for format identification tools. """
import collections

class Sha1Lookup(object):
    """ Look up class for serialsed sha1sum() results. """
    sha1_lookup = collections.defaultdict(dict)

    @classmethod
    def initialise(cls, source_path='/home/cfw/arch/data/samp/' + \
                                    'JISC/test-output/blobstore-sha1s.txt'):
        """ Clear and load the lookup table from the supplied or default source_path. """
        cls.sha1_lookup.clear()
        with open(source_path) as src_file:
            for line in src_file:
                parts = line.split(' ')
                name = parts[2][2:-1]
                sha1 = parts[0]
                if not name in cls.sha1_lookup:
                    cls.sha1_lookup.update({name : sha1})

    @classmethod
    def get_sha1(cls, name):
        """ Retrieve and return a hex SHA1 value by name. """
        return cls.sha1_lookup.get(name, None)

class MagicLookup(object):
    """ Look up class for serialised file magic results. """
    magic_lookup = collections.defaultdict(dict)

    @classmethod
    def initialise(cls, source_path='/home/cfw/arch/data/samp/JISC/test-output/file-magic.txt'):
        """ Clear and load the lookup table from the supplied or default source_path. """
        cls.magic_lookup.clear()
        with open(source_path) as src_file:
            for line in src_file:
                parts = line.split(': ')
                key = Sha1Lookup.get_sha1(parts[0].split('/')[2])
                magic_string = parts[1][:-1]
                if not key in cls.magic_lookup:
                    cls.magic_lookup.update({key : magic_string})

    @classmethod
    def get_magic_string(cls, key):
        """ Retrieve and return a magic result by key. """
        return cls.magic_lookup.get(key, None)

class MimeLookup(object):
    """ Look up class for serialised file mime results. """
    mime_lookup = collections.defaultdict(dict)

    @classmethod
    def initialise(cls, source_path='/home/cfw/arch/data/samp/JISC/test-output/file-mime.txt'):
        """ Clear and load the lookup table from the supplied or default source_path. """
        cls.mime_lookup.clear()
        with open(source_path) as src_file:
            for line in src_file:
                parts = line.split(': ')
                key = key = Sha1Lookup.get_sha1(parts[0].split('/')[2])
                mime_string = parts[1]
                if not key in cls.mime_lookup:
                    cls.mime_lookup.update({key : mime_string[:-1]})

    @classmethod
    def get_mime_string(cls, key):
        """ Retrieve and return MIME string by key. """
        return cls.mime_lookup.get(key, None)

class DroidLookup(object):
    """ Look up class for serialised droid results. """
    puid_lookup = collections.defaultdict(dict)

    @classmethod
    def initialise(cls, source_path='/home/cfw/arch/data/samp/JISC/test-output/droid/droid.txt'):
        """ Clear and load the lookup table from the supplied or default source_path. """
        cls.puid_lookup.clear()
        with open(source_path) as src_file:
            for line in src_file:
                parts = line.split(',')
                if len(parts) < 2:
                    continue
                key = Sha1Lookup.get_sha1(parts[0].split('/')[3])
                puid = parts[1][:-1]
                if not key in cls.puid_lookup:
                    cls.puid_lookup.update({key : puid})

    @classmethod
    def get_puid(cls, key):
        """ Retrieve and return PUID string by key. """
        return cls.puid_lookup.get(key, None)
