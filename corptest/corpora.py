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

# Temp hack to set up UTF-8 encoding
""" Classes to model corpora of test data, really just views on a blob store. """
import collections
from datetime import datetime
import sys

from utilities import Extension

reload(sys)
sys.setdefaultencoding('utf-8')

class CorpusItem(object):
    """ Basic attributes for a corpus item. """
    def __init__(self, sha1, size, last_modified, path):
        self.sha1 = sha1
        self.size = size
        self.last_modified = last_modified
        self.path = path.encode('utf-8')

    def get_sha1(self):
        """Returns the item's key, a unique id"""
        return self.sha1

    def get_path(self):
        """Returns the item's path."""
        return self.path

    def get_size(self):
        """Returns the size of the item in bytes"""
        return self.size

    def get_last_modified(self):
        """Returns the date the item was last modified"""
        return self.last_modified

    def __str__(self):
        ret_val = []
        ret_val.append("CorpusItem : [sha1=")
        ret_val.append(self.sha1)
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append(", last_modified=")
        ret_val.append(str(self.last_modified))
        ret_val.append(", path=")
        ret_val.append(self.path)
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for ByteSequence. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            corp_item = obj[cls_name]
            return cls(corp_item['sha1'], corp_item['size'],
                       corp_item['last_modified'], corp_item['path'])
        elif '__datetime__' in obj:
            return datetime.strptime(obj['__datetime__'], '%Y-%m-%dT%H:%M:%S')

        return obj

class Corpus(object):
    """Encapsulates corpus behaviour. Initialised with:
    name : a name for the corpus
    description : a longer description of the corpus
    elements : a Python list of elements
    """
    def __init__(self, name, description=None, items=None):
        self.name = name
        if description is None:
            description = ""
        self.description = description
        self.items = collections.defaultdict(dict)
        self.total_size = 0
        if not items is None:
            self.add_items(items)

    def get_item_count(self):
        """Returns the number of items in the corpus"""
        return len(self.items)

    def get_total_size(self):
        """Returns the total size of all items in the corpus in bytes"""
        return self.total_size

    def get_paths(self):
        """Returns the list of unique paths in the corpus."""
        return self.items.keys()

    def get_item_by_path(self, path):
        """ Lookup and retrieve item by path, returns None if no path matches. """
        return self.items.get(path, None)

    def update_sha1(self, path, sha1):
        """ Update the sha1 of an item by path. """
        item = self.get_item_by_path(path)
        item.sha1 = sha1
        self.items.update({path : item})

    def add_items(self, items):
        """ Add a list of items to the corpus. """
        for item in items:
            self.add_item(item)

    def add_item(self, item, include_json=True):
        """ Add an item to the corpus. """
        if not include_json:
            ext = Extension.from_file_name(item.path.encode('utf-8'))
            if ext.is_json():
                return
        if item.path in self.items:
            self.total_size -= self.items.get(item.path).size
        self.items.update({item.path.encode('utf-8') : item})
        self.total_size += item.size

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for Corpus. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            corpus_val = obj[cls_name]
            corpus = cls(corpus_val['name'], corpus_val['description'])
            for item in corpus_val['items'].values():
                corpus.add_item(CorpusItem.json_decode(item))
            return corpus
        return obj
