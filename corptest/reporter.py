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
"""Classes for reporting corpus results"""

from blobstore import BlobStore
from formats import Extension
import pystache

class CorpusReporter(object):
    """Class that reports the results of running format id tools across a
    corpus.
    """
    def __init__(self, items, extensions, tika_mimes, magic_mimes, magics, fido_puids):
        self.items = int(items)
        self.extensions = extensions
        self.tika_mimes = tika_mimes
        self.magic_mimes = magic_mimes
        self.magics = magics
        self.fido_puids = fido_puids

    def get_item_count(self):
        """Reports the number of items in the corpus"""
        return self.items

    def get_extensions(self):
        """Get the list of unique file extensions in the corpus"""
        mustache_list = [{"key": k, "val": v} for k, v in self.extensions.items()]
        return mustache_list

    def get_tika_mimes(self):
        """Reports the MIME types identified by Apache Tika"""
        mustache_list = [{"key": k, "val": v} for k, v in self.tika_mimes.items()]
        return mustache_list

    def get_magic_mimes(self):
        """Reports the MIME types identified by libmagic"""
        mustache_list = [{"key": k, "val": v} for k, v in self.magic_mimes.items()]
        return mustache_list

    def get_magics(self):
        """Reports the MIME types identified by libmagic"""
        mustache_list = [{"key": k, "val": v} for k, v in self.magics.items()]
        return mustache_list

    def get_fido_puids(self):
        """Reports the PRONOM types identified by FIDO"""
        mustache_list = [{"key": k, "val": v} for k, v in self.fido_puids.items()]
        return mustache_list

    def render_report(self):
        """Renders and HTML representation of the instance using a mustache
        template.
        """
        exts = self.get_extensions()
        tikas = self.get_tika_mimes()
        magic_mimes = self.get_magic_mimes()
        droids = self.get_fido_puids()
        renderer = pystache.Renderer()
        print renderer.render_path('corptest/corpus_reporter.mustache',
                                   {
                                       "exts": exts,
                                       "tikas": tikas,
                                       "magic_mimes": magic_mimes,
                                       "droids": droids
                                       })

    def __str__(self):
        ret_val = []
        ret_val.append("CorpusReporter:[items=")
        ret_val.append(str(self.items))
        ret_val.append(", extensions=")
        ret_val.append(str(len(self.extensions)))
        ret_val.append(", tika_mimes=")
        ret_val.append(str(len(self.tika_mimes)))
        ret_val.append(", magics=")
        ret_val.append(str(len(self.magics)))
        ret_val.append(", magic_mimes=")
        ret_val.append(str(len(self.magic_mimes)))
        ret_val.append(", fido_puids=")
        ret_val.append(str(len(self.fido_puids)))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def corpus_report(cls, corpus, blobstore):
        """Generates a corpus report from corpus and blobstore"""
        types = BlobStore.get_format_info()
        extensions = {}
        tika_mimes = {}
        magics = {}
        magic_mimes = {}
        fido_puids = {}
        for element in corpus.get_elements():
            if element.is_file():
                blob_name = element.get_etag()
                extension = Extension.from_file_name(element.get_key())
                if extension.get_ext() in extensions:
                    extensions[extension.get_ext()] += 1
                else:
                    extensions[extension.get_ext()] = 1
                magic = types[blob_name]["magic"]
                if str(magic) in magics:
                    magics[str(magic)] += 1
                else:
                    magics[str(magic)] = 1
                magic_mime = types[blob_name]["magic_mime"]
                if str(magic_mime) in magic_mimes:
                    magic_mimes[str(magic_mime)] += 1
                else:
                    magic_mimes[str(magic_mime)] = 1
                fido_puid_list = types[blob_name]["fido"]
                for fido_puid in fido_puid_list:
                    if fido_puid.get_puid() in fido_puids:
                        fido_puids[str(fido_puid.get_puid())] += 1
                    else:
                        fido_puids[str(fido_puid.get_puid())] = 1
        return cls(corpus.get_element_count(), extensions,
                   tika_mimes, magic_mimes, magics, fido_puids)
                # print extension.get_ext()
                # print "File MAGIC: " + str(types[blob_name]["magic"])
                # print "File MIME:  " + str(types[blob_name]["magic_mime"])
                # print "Tika MIME:  " + str()
                # fido_matches = types[blob_name]["fido"]
                # for fido_match in fido_matches:
                #     print "Fido MATCH: " +str(fido_match)
