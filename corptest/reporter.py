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
# Classes for reporting corpus results

from blobstore import BlobStore
from formats import Extension
import pystache

class CorpusReporter(object):
    def __init__(self, items, extensions, tikaMimes, magicMimes, magics, fidoPuids):
        self.items = int(items)
        self.extensions = extensions
        self.tikaMimes = tikaMimes
        self.magicMimes = magicMimes
        self.magics = magics
        self.fidoPuids = fidoPuids

    def getItemCount(self):
        return self.items

    def getExtensions(self):
        mustache_list = [{"key": k, "val": v} for k,v in self.extensions.items()]
        return mustache_list

    def getTikaMimes(self):
        mustache_list = [{"key": k, "val": v} for k,v in self.tikaMimes.items()]
        return mustache_list

    def getMagicMimes(self):
        mustache_list = [{"key": k, "val": v} for k,v in self.magicMimes.items()]
        return mustache_list

    def getMagics(self):
        mustache_list = [{"key": k, "val": v} for k,v in self.magics.items()]
        return mustache_list

    def getFidoPuids(self):
        mustache_list = [{"key": k, "val": v} for k,v in self.fidoPuids.items()]
        return mustache_list

    def renderReport(self):
        exts = self.getExtensions()
        tikas = self.getTikaMimes()
        magicMimes = self.getMagicMimes()
        droids = self.getFidoPuids()
        renderer = pystache.Renderer()
        print renderer.render_path('corptest/corpus_reporter.mustache', {"exts": exts, "tikas": tikas, "magicMimes": magicMimes, "droids": droids})

    def __str__(self):
        retVal = []
        retVal.append("CorpusReporter:[items=")
        retVal.append(str(self.items))
        retVal.append(", extensions=")
        retVal.append(str(len(self.extensions)))
        retVal.append(", tikaMimes=")
        retVal.append(str(len(self.tikaMimes)))
        retVal.append(", magics=")
        retVal.append(str(len(self.magics)))
        retVal.append(", magicMimes=")
        retVal.append(str(len(self.magicMimes)))
        retVal.append(", fidoPuids=")
        retVal.append(str(len(self.fidoPuids)))
        retVal.append("]")
        return "".join(retVal)

    @classmethod
    def corpusReport(cls, corpus,  blobstore):
        types = BlobStore.getFormatInfo()
        extensions = {}
        tikaMimes = {}
        magics = {}
        magicMimes = {}
        fidoPuids = {}
        for element in corpus.getElements():
            if element.isFile():
                blob_name = element.getEtag();
                extension = Extension.fromFileName(element.getKey())
                if extension.getExt() in extensions:
                    extensions[extension.getExt()] += 1
                else:
                    extensions[extension.getExt()] = 1
                tikaMime = types[blob_name]["tika"]
                if str(tikaMime) in tikaMimes:
                    tikaMimes[str(tikaMime)] += 1
                else:
                    tikaMimes[str(tikaMime)] = 1
                magic = types[blob_name]["magic"]
                if str(magic) in magics:
                    magics[str(magic)] += 1
                else:
                    magics[str(magic)] = 1
                magicMime = types[blob_name]["magicMime"]
                if str(magicMime) in magicMimes:
                    magicMimes[str(magicMime)] += 1
                else:
                    magicMimes[str(magicMime)] = 1
                fidoPuidList = types[blob_name]["fido"]
                for fidoPuid in fidoPuidList:
                    if fidoPuid.getPuid() in fidoPuids:
                        fidoPuids[str(fidoPuid.getPuid())] += 1
                    else:
                        fidoPuids[str(fidoPuid.getPuid())] = 1
        return cls(corpus.getElementCount(), extensions, tikaMimes, magicMimes, magics, fidoPuids)
                # print extension.getExt()
                # print "File MAGIC: " + str(types[blob_name]["magic"])
                # print "File MIME:  " + str(types[blob_name]["magicMime"])
                # print "Tika MIME:  " + str()
                # fido_matches = types[blob_name]["fido"]
                # for fido_match in fido_matches:
                #     print "Fido MATCH: " +str(fido_match)
