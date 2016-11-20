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
# Classes for scraping the corpus data from the Amazon Index page
import sys, re, requests, tempfile
from lxml import html
import xml.etree.ElementTree as ET
from const import *
from blobstore import BlobStore

# Temp hack to set up UTF-8 encoding
reload(sys)
sys.setdefaultencoding('utf-8')

class AS3Element(object):
    # Search for trailing slash to test for S3 folders
    folderPattern = re.compile('.*/$')
    def __init__(self, key, etag, size, last_modified):
        self.key = key
        self.etag = etag[1:-1]
        self.size = int(size)
        self.modified = last_modified

    def getKey(self):
        return self.key

    def getEtag(self):
        return self.etag

    def getSize(self):
        return self.size

    def getModified(self):
        return self.modified

    def isFile(self):
        return self.folderPattern.match(self.key) == None

    def __str__(self):
        retVal = []
        retVal.append("AS3Element:[key=")
        retVal.append(self.key.decode("utf-8", "ignore"))
        retVal.append(", etag=")
        retVal.append(self.etag.decode("utf-8", "ignore"))
        retVal.append(", size=")
        retVal.append(self.size.decode("utf-8", "ignore"))
        retVal.append(", modified=")
        retVal.append(self.modified.decode("utf-8", "ignore"))
        retVal.append(", isFile=")
        retVal.append(str(self.isFile()))
        retVal.append("]")
        return "".join(retVal)

    @classmethod
    def fromS3XmlContentNode(cls, node):
        retVal = mapped_dict_from_element(node, AS3Tags.PARENTS, AS3TagMap.LOOKUP)
        return AS3Element(**retVal)

class AS3Corpus(object):
    def __init__(self, root, elements):
        self.root = root
        self.elements = elements
        self.totalSize = 0
        for ele in elements:
            self.totalSize += ele.getSize()

    def getElements(self):
        return self.elements

    def getElementCount(self):
        return len(self.elements)

    def getTotalSize(self):
        return self.totalSize

    @classmethod
    def fromRootUrl(cls, rootUrl):
        elements = cls.parseElesViaTemp(rootUrl)
        return AS3Corpus(rootUrl, elements)

    @classmethod
    def parseElesViaTemp(cls, rootUrl):
        # Temp file for S3 index
        with tempfile.NamedTemporaryFile() as temp:
            fill_file_from_response(rootUrl, temp)
            # parse element tree from XML
            tree = ET.parse(temp)
            xmlRoot = tree.getroot() # root node
            return cls.elesFromTree(xmlRoot)

    @staticmethod
    def elesFromTree(tree_root):
        elements = []
        # Loop the child nodes
        for child in tree_root:
            # Strip the namespace and check to see if it's a content node
            if (strip_namespace(child.tag) == AS3Tags.CONTENTS):
                # For now just print the node
                as3Ele = AS3Element.fromS3XmlContentNode(child);
                elements.append(as3Ele)
        return elements
#
# Recursively parses an XML structure and maps tag names / tag values to the
# equivalent database field names. This info is stacked up in a dictionary that
# the fucntion returns.
# parent_tags: a list of tag values that are parents and should be recursed into
# tag_dict: a dictionary of tag-values that map to the database field name
#
def mapped_dict_from_element(root, parent_tags, tag_dict):
    mapped_dict = dict()
    for child in root:
        child_tag = strip_namespace(child.tag)
        # Parent element so recurse and merge the returned map
        if (child_tag in parent_tags):
            child_dict = mapped_dict_from_element(child, parent_tags, tag_dict)
            mapped_dict.update(child_dict)
        # Mapped element, add the value to the returned dict
        elif (child_tag in tag_dict):
            field = tag_dict[child_tag]
            mapped_dict[field] = child.text
    return mapped_dict

def strip_namespace(name):
    if (name[0] == "{"):
        # If we have a namespace strip it and return the tag
        uri, tag = name[1:].split("}")
        return tag
    else:
        return name

def fill_file_from_response(source_url, temp_file):
    # Grab the contents of the Amazon S3 bucket
    session = requests.Session()
    response = session.get(url=source_url)
    # Write response content and flush
    temp_file.write(response.content)
    temp_file.flush()
    # Reset temp for reading the XML
    temp_file.seek(0)

def main():
    corpus = AS3Corpus.fromRootUrl(SOURCE_ROOT)
    blobstore = BlobStore(BLOB_STORE_ROOT)
    totalEles = int(corpus.getElementCount())
    eleCount = 1
    downloadedBytes = 0
    print 'Starting courpus download of {0:d} items totalling {1:d} bytes.'.format(totalEles, corpus.getTotalSize())
    for element in corpus.getElements():
        print ('Downloading item number {0:d}/{1:d}, {2:d} of {3:d} bytes\r'.format(eleCount, totalEles, downloadedBytes, corpus.getTotalSize())),
        sys.stdout.flush()
        blobstore.addAS3EleBlob(SOURCE_ROOT, element)
        downloadedBytes += element.getSize();
        eleCount += 1
    print '\n'

if __name__ == "__main__":
    main()
