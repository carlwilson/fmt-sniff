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
# Classes for binary object store
import os
import urllib

class BlobStore(object):
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

    def getBlobs(self):
        onlyfiles = [f for f in os.listdir(self.root) if os.path.isfile(os.path.join(self.root, f))]
        return onlyfiles
