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
""" Tools for test corpora held in Amazon S3 buckets.

Can either:
    * scrape an Amazon S3 Index page for a list of keys; or
    * use boto3 to query the S3 API.

The utilities download any binary data and pass it to the blob store.
"""
from argparse import ArgumentParser, RawTextHelpFormatter
import collections
import errno
import json
import os.path
import sys
import re
import shutil
import tempfile

from botocore import exceptions
from boto3 import resource

from blobstore import BlobStore
from corpora import CorpusItem, Corpus
from doi import DataciteDoiLookup, DataciteDatacentre
from format_tools import Sha1Lookup
from utilities import ObjectJsonEncoder, create_dirs, Extension

from const import S3_META, EPILOG, DOI_STORE, JISC_BUCKET, BLOB_STORE_ROOT

from . import __version__

DEFAULTS = {
    'blobstore': BLOB_STORE_ROOT,
    'bucket': JISC_BUCKET,
    'description': """JISC Research Data Shared Service (RDSS) S3 corpus tools.
Tools to download and store corpus metadata and content""",
    'epilog': EPILOG,
}

class AS3Element(object):
    """Encapsulates the attributes of an Amazon S3 Storage element.
    These are analagous to files and folders on a regular file system.
    """
    # Search for trailing slash to test for S3 folders
    folderPattern = re.compile('.*/$')
    def __init__(self, key, etag, cont_type, metadata):
        self.key = key.encode('utf-8')
        self.etag = etag.encode('utf-8')
        self.content_type = cont_type.encode('utf-8')
        self.metadata = metadata

    def is_file(self):
        """Returs True if the element is a file (has binary data), False
        otherwise (the item is a folder)
        """
        return self.folderPattern.match(self.key) is None

    def __str__(self):
        ret_val = []
        ret_val.append("AS3Element : [key=")
        ret_val.append(self.key)
        ret_val.append(", etag=")
        ret_val.append(self.etag)
        ret_val.append(", content_type=")
        ret_val.append(self.content_type)
        ret_val.append(", metadata=")
        ret_val.append(str(self.metadata))
        ret_val.append(", is_file=")
        ret_val.append(str(self.is_file()))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for AS3Element. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            as3_ele = obj[cls_name]
            return cls(CorpusItem.json_decode(as3_ele['key']), as3_ele['etag'],
                       as3_ele['content_type'], as3_ele['metadata'])
        return obj

    @classmethod
    def from_s3_object(cls, s3_obj, sha1=None):
        """Create a new CorpusItem and AS3Element from a boto3 S3 key.
        """
        etag = s3_obj.e_tag[1:-1].encode('utf-8')
        if sha1 is None:
            sha1 = Sha1Lookup.get_sha1(etag)

        corpus_item = CorpusItem(sha1, s3_obj.content_length, s3_obj.last_modified,
                                 s3_obj.key.encode('utf-8'))
        s3_ele = AS3Element(s3_obj.key.encode('utf-8'), etag,
                            s3_obj.content_type.encode('utf-8'), s3_obj.metadata)
        return corpus_item, s3_ele

class AS3Corpus(object):
    """A corpus of test data downloaded from S3"""
    def __init__(self, corpus, datacentre):
        self.corpus = corpus
        self.datacentre = datacentre
        self.elements = collections.defaultdict(dict)

    def get_corpus(self):
        """ Return the contained corpus. """
        return self.corpus

    def get_element_count(self):
        """Returns the number of S3 elements in the corpus"""
        return len(self.elements)

    def get_total_size(self):
        """Returns the total size of all S3 elements in the corpus in bytes"""
        return self.corpus.get_total_size()

    def get_pair(self, etag):
        """Returns a corups intem and AS3 element pair for a given etag."""
        ele = self.elements.get(etag)
        item = self.corpus.get_item_by_path(ele.key.encode('utf-8'))
        return item, ele

    def add_s3_object(self, s3_obj):
        """ Add an S3 Object to the corpus. """
        item, element = AS3Element.from_s3_object(s3_obj)
        self.corpus.add_item(item)
        self.add_element(element)

    def add_element(self, element, include_json=False):
        # """ Add an S3 Element to the corpus. """
        if not include_json:
            ext = Extension.from_file_name(element.key.encode('utf-8'))
            if ext.is_json():
                return
        self.elements.update({element.etag : element})

    def __str__(self):
        ret_val = []
        ret_val.append("AS3Corpus : [corpus=")
        ret_val.append(str(self.corpus))
        ret_val.append(", datacentre=")
        ret_val.append(str(self.datacentre))
        ret_val.append(", elements=[")
        ele_count = 0
        for value in self.elements.values():
            if ele_count > 0:
                ret_val.append(', ')
            ret_val.append(str(value))
            ele_count += 1
        ret_val.append("]]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for AS3Corpus. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            as3_corp = obj[cls_name]
            corpus = cls(Corpus.json_decode(as3_corp['corpus']),
                         DataciteDatacentre.json_decode(as3_corp['datacentre']))
            for ele in as3_corp['elements'].values():
                corpus.add_element(AS3Element.json_decode(ele))
            return corpus
        return obj

class AS3Bucket(object):
    """Holds bucket details and a collection of contained copora."""
    UNKNOWN_KEY = "Unknown"
    CORPORA = collections.defaultdict(dict)

    @classmethod
    def get_corpus_keys(cls):
        """Returns the list of corpus keys which can be used to retrieve a
        paticular corpus.
        """
        return cls.CORPORA.keys()

    @classmethod
    def get_corpus(cls, corpus_key):
        """Lookup and retrieve a corpus by name, returns None if no corpus."""
        return cls.CORPORA.get(corpus_key, None)

    @classmethod
    def initialise(cls, bucket, persist=False):
        """Creates a new AS3Corpus from a given bucket using boto3 and
        the S3 API. It assumes that credentials and regio are supplied in
        the users home dir ~/.aws/credentials and ~/.aws/config. See boto3
        documentation for details.
        """
        Sha1Lookup.initialise()
        persist_to = cls.get_meta_file_path(bucket.name)
        if not persist:
            # No persist value passed, populate the dictionary
            cls.reload_corpora(bucket)
        elif os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            cls.load(bucket.name)
        else:
            # Persistence file doesn't exist
            create_dirs(os.path.dirname(persist_to))
            # populate and save the lookup dictionary
            cls.reload_corpora(bucket)
            cls.persist(bucket.name)

    @classmethod
    def persist(cls, name):
        """ Serialise the bucket corpora to a file called name. """
        path = cls.get_meta_file_path(name)
        with open(path, 'w') as dest:
            cls.save(dest)

    @classmethod
    def save(cls, dest):
        """ Serialise the bucket lookup dictionary to fp (a write() supporting
        file-like object). """
        json.dump(cls.CORPORA, dest, cls=ObjectJsonEncoder)

    @classmethod
    def load(cls, name):
        """ Loads the bucket from the file name in it's metadata directory."""
        path = cls.get_meta_file_path(name)
        with open(path, 'r') as src:
            cls.load_file(src)

    @classmethod
    def load_file(cls, src):
        """ Loads the datacentre lookup dictionary from fp (a read() supporting
        file like object)."""
        cls.CORPORA.clear()
        cls.SIZE = 0
        cls.CORPORA = json.load(src, object_hook=AS3Corpus.json_decode)

    @classmethod
    def reload_corpora(cls, bucket):
        """ Clear the dictionary and reload the corupus from the bucket. """
        cls.CORPORA.clear()
        DataciteDoiLookup.initialise(DOI_STORE)
        eles_processed = 0
        for key in bucket.objects.all():
            corpus_key = cls.UNKNOWN_KEY
            doi = doi_from_key(key.key)
            if not doi is None:
                corpus_key = doi
            if corpus_key not in cls.CORPORA:
                datacentre = DataciteDoiLookup.lookup_by_doi(corpus_key)
                if datacentre is None:
                    datacentre = DataciteDatacentre(cls.UNKNOWN_KEY, corpus_key,
                                                    cls.UNKNOWN_KEY)
                corpus = Corpus(datacentre.doi, datacentre.name)
                s3_corpus = AS3Corpus(corpus, datacentre)
                cls.CORPORA.update({corpus_key : s3_corpus})

            s3_corpus = cls.CORPORA.get(corpus_key)
            s3_corpus.add_s3_object(key.Object())
            eles_processed += 1
            print ('Reloading S3 corpus, item number : {:d}\r').format(eles_processed),
            sys.stdout.flush()

    @classmethod
    def get_meta_file_path(cls, name):
        """ Return the path to the corpus metadata file. """
        return S3_META + name

    @classmethod
    def download_bucket(cls, bucket):
        """ Download corpus content from the bucket. """
        total_eles = 0
        total_size = 0
        BlobStore.initialise(BLOB_STORE_ROOT, persist=True)
        for key in cls.CORPORA.keys():
            corpus = cls.CORPORA.get(key)
            cls.download_corpus(bucket, corpus)
            total_eles += corpus.get_element_count()
            total_size += corpus.get_total_size()
        print chr(27) + "[2K"
        print ('Downloaded {0:d} items totalling {1:d} bytes from ' + \
               'corpus.').format(total_eles, total_size)

    @classmethod
    def download_corpus(cls, bucket, corpus):
        """Downloads the contents of corpus into the BLOB store."""
        total_eles = int(corpus.get_element_count())
        ele_count = 0
        downloaded_bytes = 0
        print ("\nStarting courpus download of {0:d} items " + \
               "totalling {1:d} bytes.").format(total_eles, corpus.get_total_size())
        tmpdir = tempfile.mkdtemp()
        try:
            for etag in corpus.elements.keys():
                item, element = corpus.get_pair(etag)
                downloaded_bytes += item.size
                ele_count += 1
                print ('Downloading item number {0:d}/{1:d}, {2:d} of ' + \
                '{3:d} bytes\r').format(ele_count, total_eles,
                                        downloaded_bytes,
                                        corpus.get_total_size()),
                sys.stdout.flush()
                if BlobStore.get_blob(etag) is None:
                    filename = cls.download_s3_ele_from_bucket(bucket, element, tmpdir)
                    BlobStore.add_file(filename, element.key, item.sha1)
        finally:
            try:
                shutil.rmtree(tmpdir)
            except OSError as excep:
                if excep.errno != errno.ENOENT:
                    raise

    @classmethod
    def download_s3_ele_from_bucket(cls, bucket, ele, directory):
        """Add a new BLOB from an S3 element"""
        if not ele.is_file():
            return
        filename = os.path.join(directory, ele.etag)
        bucket.download_file(ele.key, filename)
        return filename

def doi_from_key(key):
    """ Parse the key part from an Amazon s3 key. """
    doi = None
    key_parts = key.split('/')
    if len(key_parts) > 2:
        doi = key_parts[1]
    return doi

def get_s3_bucket_by_name(bucket_name):
    """ Get an S3 bucket by name """
    s3_resource = resource('s3')
    return validate_return_s3_bucket(s3_resource, bucket_name)

def validate_return_s3_bucket(s3_resource, bucket_name):
    """Retrieve the bucket named bucket_name from the passed s3_resource and
    validate it could be found (no 404) before returning the bucket.
    """
    bucket = s3_resource.Bucket(bucket_name)
    exists = True
    try:
        s3_resource.meta.client.head_bucket(Bucket=bucket_name)
    except exceptions.ClientError as boto_excep:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(boto_excep.response['Error']['Code'])
        if error_code == 404:
            exists = False
    return exists, bucket

def main(args=None):
    """Main method entry point."""
    if not args:
        args = sys.argv[1:]

    parser = ArgumentParser(description=DEFAULTS['description'],
                            epilog=DEFAULTS['epilog'],
                            fromfile_prefix_chars='@',
                            formatter_class=RawTextHelpFormatter)
    parser.add_argument('-v', '--version', default=False, action='store_true',
                        help='show version information')
    parser.add_argument('-d', '--download', default=False, action='store_true',
                        help='download the corpus data and content')
    parser.add_argument('-l', '--list', default=False, action='store_true',
                        help='list all of the corpora')
    parser.add_argument('-b', '--bucket', default=DEFAULTS['bucket'],
                        help='name of a bucket to use as corpus root')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    version_header = "S3 Corpora v{0}\n".format(__version__)

    if args.version:
        sys.stdout.write(version_header)
        sys.exit(0)

    if args.download:
        bucket_name = args.bucket
        bucket_exists, bucket = get_s3_bucket_by_name(bucket_name)
        if not bucket_exists:
            sys.exit('No AS3 bucket called {} found.'.format(bucket_name))
        AS3Bucket.initialise(bucket, persist=True)
        AS3Bucket.download_bucket(bucket)

if __name__ == "__main__":
    main()
