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
""" Classes for Tool Result lookup. """
import collections
import json
import os.path

from corptest import APP # pylint: disable-msg=W0403
from .formats import ToolResult
from .utilities import ObjectJsonEncoder, create_dirs

RDSS_ROOT = APP.config.get('RDSS_ROOT')
RESULTS_ROOT = os.path.join(RDSS_ROOT, 'results')
BLOB_STORE_ROOT = os.path.join(RDSS_ROOT, 'blobstore')
class ToolRegistry(object):
    """ Lookup tools by name and version. """

    def __init__(self, tools=None):
        if tools is None:
            tools = []
        self.tools = {}
        self.add_tools(tools)

    def tool_by_name(self, name):
        """ Lookup an return the first tool by name. """
        return self.tools.get(name, None)

    def add_tool(self, tool):
        """Add a tool to the registry."""
        self.tools.update({tool.name : tool})

    def add_tools(self, tools):
        """Add a list of tools to the registry. """
        for tool in tools:
            self.add_tool(tool)

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

# def main():
#     """
#     Main method entry point.
#     """
#     PronomId.initialise()
#
#     tool_registry = ToolRegistry([FormatTool("file", "5.25"), FormatTool("tika", "1.14"),
#                                   FormatTool("droid", "6.3"), FormatTool("fido", "1.3.5"),
#                                   FormatTool("python-magic", "0.4.12")])
#
#     blobstore = BlobStore(BLOB_STORE_ROOT)
#     ResultRegistry.initialise(persist=True)

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
#     ele_count = 0
#     total_eles = blobstore.blob_count
#     PronomId.initialise()
#     for key in blobstore.blobs.keys():
#         ele_count += 1
#         print(('Identifying blob {0:d} of {1:d}\r').format(ele_count, total_eles),)
#         blob = blobstore.get_blob(key)
#         sha_1 = blob.get_sha1()
#         path = blobstore.get_blob_path(key)
#         mime_type = MimeType.from_file_by_magic(path)
#         magic_type = MagicType.from_file_by_magic(path)
#         py_magic_result = ToolResult(tool_registry.tool_by_name("python-magic"),
#                                      mime_type, magic_type, PronomId.get_default())
#         ResultRegistry.add_result(sha_1, "python-magic", py_magic_result)
#         fido_types = PronomId.from_file_by_fido(path)
#         if fido_types:
#             pronom_result = fido_types[0]
#             pronom_result = PronomId.get_pronom_type(pronom_result.puid)
#             mime_type = MimeType.get_default()
#             if not pronom_result is None and not pronom_result.mime is None:
#                 mime_type = MimeType.from_mime_string(pronom_result.mime)
#             fido_result = ToolResult(tool_registry.tool_by_name("fido"), mime_type,
#                                      MagicType.get_default(), pronom_result)
#             ResultRegistry.add_result(sha_1, "fido-nocont", fido_result)
#     ResultRegistry.persist()
#
# if __name__ == "__main__":
#     main()
