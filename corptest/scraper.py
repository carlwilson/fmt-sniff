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
"""Amazon S3 concepts and utilities

Can either:
    * scrape an Amazon S3 Index page for a list of keys; or
    * use boto3 to query the S3 API.

The uitilities download andy binary data and passes it to the blob store.
"""
import sys
import re
import tempfile
import xml.etree.ElementTree as ET
import requests
from blobstore import BlobStore
from const import BLOB_STORE_ROOT, JISC_BUCKET, AS3TagMap, AS3Tags
from reporter import CorpusReporter
from botocore import exceptions
from boto3 import resource

# Temp hack to set up UTF-8 encoding
reload(sys)
sys.setdefaultencoding('utf-8')

class AS3Element(object):
    """Encapsulates the attributes of an Amazon S3 Storage element.
    These are analagous to files and folders on a regular file system.
    """
    # Search for trailing slash to test for S3 folders
    folderPattern = re.compile('.*/$')
    def __init__(self, key, etag, size, last_modified):
        self.key = key
        self.etag = etag[1:-1]
        self.size = int(size)
        self.modified = last_modified

    def get_key(self):
        """Returns the element's S3 key, effectively a name / path"""
        return self.key

    def get_etag(self):
        """Returns the elements etag which is usually its MD5"""
        return self.etag

    def get_size(self):
        """Returns the size of the element in bytes"""
        return self.size

    def get_modified(self):
        """Returns the date the item was last modified"""
        return self.modified

    def is_file(self):
        """Returs True if the element is a file (has binary data), False
        otherwise (the item is a folder)
        """
        return self.folderPattern.match(self.key) is None

    def __str__(self):
        ret_val = []
        ret_val.append("AS3Element:[key=")
        ret_val.append(self.key.decode("utf-8", "ignore"))
        ret_val.append(", etag=")
        ret_val.append(self.etag.decode("utf-8", "ignore"))
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append(", modified=")
        ret_val.append(self.modified.decode("utf-8", "ignore"))
        ret_val.append(", is_file=")
        ret_val.append(str(self.is_file()))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def from_s3_xml_content_node(cls, node):
        """Create a new AS3Element instance from an XML fragment parsed from
        the S3 index page.
        """
        ret_val = mapped_dict_from_element(node, AS3Tags.PARENTS, AS3TagMap.LOOKUP)
        return AS3Element(**ret_val)

    @classmethod
    def from_boto_key(cls, key):
        """Create a new AS3Element instance from a boto3 S3 key.
        """
        return AS3Element(key.key, key.e_tag, key.size, key.last_modified)

class AS3Corpus(object):
    """A corpus of test data downloaded from S3"""
    def __init__(self, root, elements):
        self.root = root
        self.elements = elements
        self.total_size = 0
        for ele in elements:
            self.total_size += ele.get_size()

    def get_elements(self):
        """Returns the list of S3 elements in the corpus"""
        return self.elements

    def get_element_count(self):
        """Returns the number of S3 elements in the corpus"""
        return len(self.elements)

    def get_total_size(self):
        """Returns the total size of all S3 elements in the corpus in bytes"""
        return self.total_size

    @classmethod
    def from_s3_bucket(cls, bucket):
        """Creates a new AS3Corpus from a given bucket using boto3 and
        the S3 API. It assumes that credentials and regio are supplied in
        the users home dir ~/.aws/credentials and ~/.aws/config. See boto3
        documentation for details.
        """
        elements = []
        for key in bucket.objects.all():
            print "Element:" + str(key.key)
            s3_ele = AS3Element.from_boto_key(key)
            elements.append(s3_ele)
        return AS3Corpus(bucket.name, elements)

    @classmethod
    def from_root_url(cls, root_url):
        """Creates a new AS3Corpus from a root URL that locates the
        S3 Index page.
        """
        elements = cls.parse_eles_via_temp(root_url)
        return AS3Corpus(root_url, elements)

    @classmethod
    def parse_eles_via_temp(cls, root_url):
        """Parses the S3 index located at root_url and parses it to populate the
        corpus. It caches the HTTP response from root_url to a temp file for
        parsing
        """
        # Temp file for S3 index
        with tempfile.NamedTemporaryFile() as temp:
            fill_file_from_response(root_url, temp)
            # parse element tree from XML
            tree = ET.parse(temp)
            xml_root = tree.getroot() # root node
            return cls.eles_from_tree(xml_root)

    @staticmethod
    def eles_from_tree(tree_root):
        """Finds all XML elements below tree_root and returns them as a list"""
        elements = []
        # Loop the child nodes
        for child in tree_root:
            # Strip the namespace and check to see if it's a content node
            if strip_namespace(child.tag) == AS3Tags.CONTENTS:
                # For now just print the node
                s3_ele = AS3Element.from_s3_xml_content_node(child)
                elements.append(s3_ele)
        return elements

def mapped_dict_from_element(root, parent_tags, tag_dict):
    """Recursively parses an XML structure and maps tag names / tag values to the
    equivalent database field names. This info is stacked up in a dictionary that
    the fucntion returns.
    parent_tags: a list of tag values that are parents and should be recursed into
    tag_dict: a dictionary of tag-values that map to the database field name
    """
    mapped_dict = dict()
    for child in root:
        child_tag = strip_namespace(child.tag)
        # Parent element so recurse and merge the returned map
        if child_tag in parent_tags:
            child_dict = mapped_dict_from_element(child, parent_tags, tag_dict)
            mapped_dict.update(child_dict)
        # Mapped element, add the value to the returned dict
        elif child_tag in tag_dict:
            field = tag_dict[child_tag]
            mapped_dict[field] = child.text
    return mapped_dict

def strip_namespace(name):
    """Strips the namespace from a tag and returns the stripped tag"""
    if name[0] == "{":
        # If we have a namespace strip it and return the tag
        uri, tag = name[1:].split("}")
        return tag
    else:
        return name

def fill_file_from_response(source_url, temp_file):
    """HTTP get from source_url and writes the resoponse to temp_file"""
    # Grab the contents of the Amazon S3 bucket
    session = requests.Session()
    response = session.get(url=source_url)
    # Write response content and flush
    temp_file.write(response.content)
    temp_file.flush()
    # Reset temp for reading the XML
    temp_file.seek(0)

def get_s3_bucket_by_name(bucket_name):
    """Get an S3 bucket by name"""
    s3_resource = resource('s3')
    print "Loading bucket index"
    return validate_return_s3_bucket(s3_resource, bucket_name)

def validate_return_s3_bucket(s3_resource, bucket_name):
    """Retrieve the bucket named bucket_name from the passed s3_resource and
    validate it could be found (no 404) before returning the bucket.
    """
    bucket = s3_resource.Bucket(bucket_name)
    exists = True
    try:
        s3_resource.meta.client.head_bucket(Bucket='testdata.researchdata.alpha.jisc.ac.uk')
    except exceptions.ClientError as boto_excep:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(boto_excep.response['Error']['Code'])
        if error_code == 404:
            exists = False
    if exists:
        return bucket

def main():
    """Main method entry point"""
    bucket = get_s3_bucket_by_name(JISC_BUCKET)
    corpus = AS3Corpus.from_s3_bucket(bucket)
    print "Loading corpus data from S3"
    blobstore = BlobStore(BLOB_STORE_ROOT)
    blobstore.load_corpus(corpus, bucket)
#    print "hash checking BLOB store"
#    blobstore.hash_check()
    print "Running blobstore format identification"
    blobstore.identify_contents()
    print "Preparing report"
    reporter = CorpusReporter.corpus_report(corpus, blobstore)
    print "Rendering report"
    reporter.render_report()

if __name__ == "__main__":
    main()
