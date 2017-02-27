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
""" Classes for Tool Result lookup. """
import collections
import json
import os.path

from blobstore import BlobStore
from const import RESULTS_ROOT, BLOB_STORE_ROOT
from formats import FormatTool, MagicType, MimeType, ToolResult, PronomId
from utilities import ObjectJsonEncoder, create_dirs

class ToolRegistry(object):
    """ Lookup tools by name and version. """
    TOOLS = collections.defaultdict(dict)

    @classmethod
    def tool_by_name(cls, name):
        """ Lookup an return the first tool by name. """
        return cls.TOOLS.get(name, None)

    @classmethod
    def initialise(cls, persist=False, tools=None):
        """ If persist is True tries to load a serialised lookup table and adds tools.
        Populates lookup table and saves if persist is True.
        """
        if tools is None:
            tools = []

        if not persist:
            # No persist requested, populate the dictionary
            cls.TOOLS = tools
            return

        persist_to = cls.get_persist_path()
        if os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            with open(persist_to, 'r') as lookup_file:
                cls.load(lookup_file)
        else:
            # Persistence file doesn't exist
            create_dirs(os.path.dirname(persist_to))

        for tool in tools:
            cls.TOOLS.update({tool.name : tool})

        with open(persist_to, 'w+') as lookup_file:
            cls.save(lookup_file)

    @classmethod
    def save(cls, dest):
        """ Serialise the datacentre lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(cls.TOOLS, dest, cls=ObjectJsonEncoder)

    @classmethod
    def load(cls, src):
        """ Loads the lookup dictionary from fp (a read() supporting
        file like object)."""
        cls.TOOLS.clear()
        cls.TOOLS = json.load(src, object_hook=FormatTool.json_decode)

    @classmethod
    def get_persist_path(cls):
        """ Returns the persistent JSON metadata file path. """
        return RESULTS_ROOT + cls.__name__ + '.json'

class ResultRegistry(object):
    """ Record and lookup tool results by sha-1. """
    RESULTS = collections.defaultdict(dict)

    @classmethod
    def add_result(cls, sha1, tool, result):
        """ Add a new result to the convoluted results dictionary. """
        if sha1 in cls.RESULTS.keys():
            cls.RESULTS[sha1].update({tool : result})
        else:
            cls.RESULTS.update({sha1 : {tool : result}})

    @classmethod
    def results_for_sha1(cls, sha1):
        """ Returns the result set for a give SHA1 hex value. """
        return cls.RESULTS.get(sha1, None)

    @classmethod
    def initialise(cls, persist=False):
        """ If persist is True tries to load a serialised lookup table.  """
        if not persist:
            return

        load_from = cls.get_persist_path()
        if os.path.isfile(load_from):
            # Persistence file exists, load the dictionary
            with open(load_from, 'r') as lookup_file:
                cls.load(lookup_file)
        else:
            # Persistence file doesn't exist, create the parent dirs
            create_dirs(os.path.dirname(load_from))

    @classmethod
    def persist(cls):
        """ Save to default location. """
        with open(cls.get_persist_path(), 'w+') as lookup_file:
            cls.save(lookup_file)

    @classmethod
    def save(cls, dest):
        """ Serialise the datacentre lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(cls.RESULTS, dest, cls=ObjectJsonEncoder)

    @classmethod
    def load(cls, src):
        """ Loads the lookup dictionary from fp (a read() supporting
        file like object)."""
        cls.RESULTS.clear()
        cls.RESULTS = json.load(src, object_hook=ToolResult.json_decode)

    @classmethod
    def get_persist_path(cls):
        """ Returns the persistent JSON metadata file path. """
        return RESULTS_ROOT + cls.__name__ + '.json'

def main():
    """
    Main method entry point.
    """
    PronomId.initialise()

    ToolRegistry.initialise(tools=[FormatTool("file", "5.25"), FormatTool("tika", "1.14"),
                                   FormatTool("droid", "6.3"), FormatTool("fido", "1.3.5"),
                                   FormatTool("python-magic", "0.4.12")], persist=True)

    BlobStore.initialise(BLOB_STORE_ROOT, persist=True)
    ResultRegistry.initialise(persist=True)

    # item_count = 0
    # byte_count = 0
    # for key in BlobStore.BLOBS.keys():
    #     blob = BlobStore.get_blob(key)
    #     sha_1 = blob.byte_sequence.sha_1
    #     item_count += 1
    #     byte_count += blob.byte_sequence.size
    #     print ('Processing item number {0:d}/{1:d}, {2:d} of ' + \
    #     '{3:d} bytes\r').format(item_count, BlobStore.get_blob_count(),
    #                             byte_count,
    #                             BlobStore.get_total_blob_size()),
    #     sys.stdout.flush()
    #
    #     magic = MagicLookup.get_magic_string(sha_1)
    #     mime_string = MimeLookup.get_mime_string(sha_1)
    #     mime = MimeType.from_mime_string(mime_string)
    #     file_result = ToolResult(FormatTool("file", "5.25"), mime, magic, PronomId.get_default())
    #     ResultRegistry.add_result(sha_1, "file", file_result)
    #
    #     pronom_id = DroidLookup.get_puid(sha_1)
    #     pronom_result = FidoUtils.get_pronom_type(pronom_id)
    #     mime = MimeType.get_default()
    #     if not pronom_result is None and not pronom_result.mime is None:
    #         mime = MimeType.from_mime_string(pronom_result.mime)
    #     droid_result = ToolResult(FormatTool("droid", "6.3"),
    #                               mime, MagicType.get_default(), pronom_result)
    #     ResultRegistry.add_result(sha_1, "droid", droid_result)
    #
    # ResultRegistry.persist()
    ele_count = 0
    total_eles = BlobStore.get_blob_count()
    PronomId.initialise()
    for key in BlobStore.BLOBS.keys():
        ele_count += 1
        print ('Identifying blob {0:d} of {1:d}\r').format(ele_count, total_eles),
        blob = BlobStore.get_blob(key)
        sha_1 = blob.byte_sequence.sha_1
        path = BlobStore.get_blob_path(key)
        # mime_type = MimeType.from_file_by_magic(path)
        # magic_type = MagicType.from_file_by_magic(path)
        # py_magic_result = ToolResult(FormatTool("python-magic", "0.4.12"),
        #                              mime_type, magic_type, PronomId.get_default())
        # ResultRegistry.add_result(sha_1, "python-magic", py_magic_result)
        fido_types = PronomId.from_file_by_fido(path)
        if len(fido_types) > 0:
            pronom_result = fido_types[0]
            pronom_result = PronomId.get_pronom_type(pronom_result.puid)
            mime_type = MimeType.get_default()
            if not pronom_result is None and not pronom_result.mime is None:
                mime_type = MimeType.from_mime_string(pronom_result.mime)
        # mime_string = TikaLookup.mime_lookup.get(sha_1)
        # mime_type = MimeType.from_mime_string(mime_string)
        fido_result = ToolResult(FormatTool("fido", "1.3.5"), mime_type,
                                 MagicType.get_default(), pronom_result)
        ResultRegistry.add_result(sha_1, "fido-nocont", fido_result)
    ResultRegistry.persist()

if __name__ == "__main__":
    main()
