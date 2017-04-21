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

from corptest.blobstore import BlobStore, ByteSequence
from corptest.corpora import CorpusItem, Corpus
from corptest.utilities import ObjectJsonEncoder, create_dirs, Extension
from corptest.const import S3_META, EPILOG, JISC_BUCKET, BLOB_STORE_ROOT

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
    def from_s3_object(cls, s3_obj, sha1=ByteSequence.EMPTY_SHA1):
        """Create a new CorpusItem and AS3Element from a boto3 S3 key.
        """
        etag = s3_obj.e_tag[1:-1].encode('utf-8')
        corpus_item = CorpusItem(sha1, s3_obj.content_length, s3_obj.last_modified,
                                 s3_obj.key.encode('utf-8'))
        s3_ele = AS3Element(s3_obj.key.encode('utf-8'), etag,
                            s3_obj.content_type.encode('utf-8'), s3_obj.metadata)
        return corpus_item, s3_ele

class AS3Corpus(object):
    """A corpus of test data downloaded from S3"""
    def __init__(self, corpus, doi):
        self.corpus = corpus
        self.doi = doi
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

    def get_pairs(self, include_json=True):
        """Generator that iterates through the corpus and S3 pairs. """
        for etag in self.elements.keys():
            element = self.elements.get(etag)
            if not include_json:
                ext = Extension.from_file_name(element.key.encode('utf-8'))
                if ext.is_json():
                    continue
            yield self.get_pair(etag)

    def get_pair(self, etag):
        """Returns a corups intem and AS3 element pair for a given etag."""
        element = self.elements.get(etag)
        item = self.corpus.get_item_by_path(element.key.encode('utf-8'))
        return item, element

    def update_sha1(self, etag, sha1):
        """ Updates the sha1 of an item by etag. """
        ele = self.elements.get(etag)
        self.corpus.update_sha1(ele.key.encode('utf-8'), sha1)

    def add_s3_object(self, s3_obj):
        """ Add an S3 Object to the corpus. """
        item, element = AS3Element.from_s3_object(s3_obj)
        self.corpus.add_item(item)
        self.add_element(element)

    def add_element(self, element):
        """ Add an S3 Element to the corpus. """
        self.elements.update({element.etag : element})

    def __str__(self):
        ret_val = []
        ret_val.append("AS3Corpus : [corpus=")
        ret_val.append(str(self.corpus))
        ret_val.append(", doi=")
        ret_val.append(str(self.doi))
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
            corpus = cls(Corpus.json_decode(as3_corp['corpus']), as3_corp['doi'])
            for ele in as3_corp['elements'].values():
                corpus.add_element(AS3Element.json_decode(ele))
            return corpus
        return obj

class AS3Bucket(object):
    """Holds bucket details and a collection of contained copora."""
    UNKNOWN_KEY = "Unknown"
    def __init__(self, bucket_name, persist=False):
        self.bucket_name = bucket_name
        self.persist = persist
        self.size = 0
        self.corpora = collections.defaultdict(dict)
        self.initialise()

    def get_corpus_keys(self):
        """Returns the list of corpus keys which can be used to retrieve a
        paticular corpus.
        """
        return self.corpora.keys()

    def get_corpus(self, corpus_key):
        """Lookup and retrieve a corpus by name, returns None if no corpus."""
        return self.corpora.get(corpus_key, None)

    def get_corpora(self):
        """Python generator function that returns the corpora."""
        for corpus in self.corpora.values():
            yield corpus

    def initialise(self):
        """Creates a new AS3Corpus from a given bucket using boto3 and
        the S3 API. It assumes that credentials and regio are supplied in
        the users home dir ~/.aws/credentials and ~/.aws/config. See boto3
        documentation for details.
        """
        if not self.persist:
            # No persist value passed, populate the dictionary
            self.reload()
            return

        persist_to = self.get_meta_file_path()
        if os.path.isfile(persist_to):
            # Persistence file exists, load the dictionary
            self.load()
        else:
            # Persistence file doesn't exist
            create_dirs(os.path.dirname(persist_to))
            # populate and save the lookup dictionary
            self.reload()
            self.save()

    def save(self):
        """ Serialise the bucket corpora to a file called name. """
        path = self.get_meta_file_path()
        with open(path, 'w') as dest:
            json.dump(self.corpora, dest, cls=ObjectJsonEncoder)

    def load(self):
        """ Loads the bucket from the file name in it's metadata directory."""
        path = self.get_meta_file_path()
        with open(path, 'r') as src:
            self.corpora.clear()
            self.size = 0
            self.corpora = json.load(src, object_hook=AS3Corpus.json_decode)

    def reload(self):
        """ Clear the dictionary and reload the corupus from the bucket. """
        bucket_exists, bucket = self.validate_and_return_bucket(self.bucket_name)
        if not bucket_exists:
            raise IOError('No AS3 bucket called {} found.'.format(self.bucket_name))

        self.corpora.clear()
        eles_processed = 0
        batch = eles_processed + 1000
        for key in bucket.objects.all():
            corpus_key = self.UNKNOWN_KEY
            doi = doi_from_key(key.key)
            if not doi is None:
                corpus_key = doi
            if corpus_key not in self.corpora:
                corpus = Corpus(doi)
                s3_corpus = AS3Corpus(corpus, doi)
                self.corpora.update({corpus_key : s3_corpus})

            s3_corpus = self.corpora.get(corpus_key)
            s3_corpus.add_s3_object(key.Object())
            eles_processed += 1
            sys.stdout.write('Reloading S3 corpus, item number : {:d}\r'.format(eles_processed))
            sys.stdout.flush()
            if eles_processed > batch:
                self.save()
                batch = eles_processed + 1000
        self.save()

    def get_meta_file_path(self):
        """ Return the path to the corpus metadata file. """
        return S3_META + self.bucket_name

    @classmethod
    def validate_and_return_bucket(cls, bucket_name):
        """Retrieve the bucket named bucket_name from the passed s3_resource and
        validate it could be found (no 404) before returning the bucket.
        """
        s3_resource = resource('s3')
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

    def download_bucket(self, blobstore):
        """ Download corpus content from the bucket. """
        total_eles = 0
        total_size = 0
        for corpus in self.get_corpora():
            self.download_corpus(corpus, blobstore)
            total_eles += corpus.get_element_count()
            total_size += corpus.get_total_size()
            sys.stdout.write(chr(27) + "[2K")
            sys.stdout.write(
                'Downloading {0:d} items totalling {1:d} bytes from bucket.'.format(total_eles,
                                                                                    total_size))
            sys.stdout.flush()

    def download_corpus(self, corpus, blobstore):
        """Downloads the contents of corpus into the BLOB store."""
        bucket_exists, bucket = self.validate_and_return_bucket(self.bucket_name)
        if not bucket_exists:
            raise IOError('No AS3 bucket called {} found.'.format(self.bucket_name))

        total_eles = int(corpus.get_element_count())
        ele_count = 0
        downloaded_bytes = 0
        sys.stdout.write(
            ('\nDownloading {0:d} items totalling {1:d} bytes.\n').format(total_eles,
                                                                          corpus.get_total_size()))
        sys.stdout.flush()
        tmpdir = tempfile.mkdtemp()
        try:
            for item, element in corpus.get_pairs():
                etag = element.etag
                downloaded_bytes += item.size
                ele_count += 1
                print(('Downloading item number {0:d}/{1:d}, {2:d} of ' + \
                '{3:d} bytes\r').format(ele_count, total_eles,
                                        downloaded_bytes,
                                        corpus.get_total_size()),)
                sys.stdout.flush()
                if item.sha1 != ByteSequence.EMPTY_SHA1:
                    if blobstore.get_blob(item.sha1) is not None:
                        continue
                filename = self.download_s3_ele_from_bucket(bucket, element, tmpdir)
                sha1 = blobstore.add_file(filename)
                corpus.update_sha1(etag, sha1)
        finally:
            try:
                shutil.rmtree(tmpdir)
            except OSError as excep:
                if excep.errno != errno.ENOENT:
                    raise
        self.save()
        blobstore.persist()

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

def main(args=None):
    """Main method entry point."""
    if not args:
        args = sys.argv[1:]

    parser = ArgumentParser(description=DEFAULTS['description'],
                            epilog=DEFAULTS['epilog'],
                            fromfile_prefix_chars='@',
                            formatter_class=RawTextHelpFormatter)
    parser.add_argument('-v', '--version', default=False, action='store_true',
                        help='show version information and exits')
    parser.add_argument('-d', '--download', default=False, action='store_true',
                        help='download the corpus data and content')
    parser.add_argument('--defaults', default=False, action='store_true',
                        help='show the default values and exits')
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

    if args.defaults:
        sys.stdout.write('Bucket: {}\n'.format(DEFAULTS['bucket']))
        sys.stdout.write('BlobStore: {}\n'.format(DEFAULTS['blobstore']))
        sys.exit(0)

    bucket_name = args.bucket
    sys.stdout.write('Initialising bucket: {}\n'.format(bucket_name))
    sys.stdout.flush()
    as3_bucket = AS3Bucket(bucket_name, persist=True)

    if args.download:
        sys.stdout.write('Initialising blobstore: {}\n'.format(BLOB_STORE_ROOT))
        sys.stdout.flush()
        blobstore = BlobStore(BLOB_STORE_ROOT)
        sys.stdout.write('Downloading bucket: {}\n'.format(bucket_name))
        sys.stdout.flush()
        as3_bucket.download_bucket(blobstore)

    if args.list:
        for corpus in as3_bucket.get_corpora():
            sys.stdout.write('{} : {}\n'.format(corpus.datacentre.doi, corpus.datacentre.name))

if __name__ == "__main__":
    main()
