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
# http://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file
# Classes for binary object store
import sys, os, collections
import urllib
import hashlib
from formats import MimeType, MagicType, PronomId
from const import *

class BlobStore(object):
    FORMAT_INFO = collections.defaultdict(dict)
    def __init__(self, rootDir):
        if not os.path.isdir(rootDir):
            os.makedirs(rootDir)
        self.root = rootDir

    def addAS3EleBlob(self, rootUrl, ele):
        if not ele.isFile():
            return
        filename = self.root + ele.getEtag()
        if os.path.isfile(filename):
            return
        location = rootUrl + ele.getKey().encode("utf-8")
        downloader = urllib.URLopener()
        downloader.retrieve(location, filename)

    def getRoot(self):
        return self.root

    def getBlobNames(self):
        onlyfiles = [f for f in os.listdir(self.root) if os.path.isfile(os.path.join(self.root, f))]
        return onlyfiles

    def getBlobPath(self, blob_name):
        return self.root + blob_name

    def hashCheck(self):
        fnamelst = self.getBlobNames()
        tuples_to_check = [(fname, hashfile(open(self.root + fname, 'rb'), hashlib.md5())) for fname in fnamelst]
        for to_check in tuples_to_check:
            if (to_check[0] != to_check[1]) :
                print "Digest mis-maatch for file " + self.root + to_check[0] + ", calculated: " + to_check[1]

    def identifyContents(self):
        for blob_name in self.getBlobNames():
            blob_path = self.getBlobPath(blob_name)
            mimeType = MimeType.fromFileByMagic(self.getBlobPath(blob_name))
            magicType = MagicType.fromFileByMagic(self.getBlobPath(blob_name))
            tikaType = MimeType.fromFileByTika(self.getBlobPath(blob_name))
            fidoTypes = PronomId.fromFileByFido(self.getBlobPath(blob_name))
            self.FORMAT_INFO[blob_name]['magic'] = magicType
            self.FORMAT_INFO[blob_name]['magicMime'] = mimeType
            self.FORMAT_INFO[blob_name]['tika'] = tikaType
            self.FORMAT_INFO[blob_name]['fido'] = fidoTypes

    def loadCorpus(self, corpus):
        totalEles = int(corpus.getElementCount())
        eleCount = 1
        downloadedBytes = 0
        print ('Starting courpus download of {0:d} items totalling {1:d} bytes.'.format(totalEles, corpus.getTotalSize()))
        for element in corpus.getElements():
            print ('Downloading item number {0:d}/{1:d}, {2:d} of {3:d} bytes\r'.format(eleCount, totalEles, downloadedBytes, corpus.getTotalSize())),
            sys.stdout.flush()
            self.addAS3EleBlob(SOURCE_ROOT, element)
            downloadedBytes += element.getSize();
            eleCount += 1
        print(chr(27) + "[2K")
        print 'Downloaded {0:d} items totalling {1:d} bytes inot corpus.'.format(totalEles, corpus.getTotalSize())

    @classmethod
    def getFormatInfo(cls):
        return cls.FORMAT_INFO

def hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()
