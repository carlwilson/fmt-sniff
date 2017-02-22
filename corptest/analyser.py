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
"""Slicing and dicing of corpus testing results for reporting."""
from argparse import ArgumentParser, RawTextHelpFormatter
import collections
import sys

import numpy as np

from blobstore import BlobStore
from const import EPILOG, JISC_BUCKET, BLOB_STORE_ROOT
from registries import ResultRegistry
from s3_corpora import AS3Bucket, get_s3_bucket_by_name
from utilities import sizeof_fmt

from . import __version__

DEFAULTS = {
    'blobstore': BLOB_STORE_ROOT,
    'bucket': JISC_BUCKET,
    'description': """JISC Research Data Shared Service (RDSS) Format Analyser.
Statistical tools for blobstore, corpus and format result data.""",
    'epilog': EPILOG,
}

class BucketAnalyser(object):
    """ Analyses an S3 bucket. """

    @classmethod
    def summarise(cls, bucket_name, group_unknown=False):
        """Create bucket summary, number of corpora, number and size of contents."""
        corpus_count = element_count = total_size = 0
        unknown_dois = []
        for key in AS3Bucket.get_corpus_keys():
            corpus = AS3Bucket.get_corpus(key)
            element_count += corpus.get_element_count()
            total_size += corpus.get_total_size()
            if group_unknown and corpus.datacentre.name == 'Unknown':
                unknown_dois.append(corpus.datacentre.doi)
                continue
            print 'DOI: {}, Name: {}, '.format(corpus.datacentre.doi,
                                               corpus.datacentre.name) + \
                  '{} items totalling {}.'.format(corpus.get_element_count(),
                                                  sizeof_fmt(corpus.get_total_size()))
            corpus_count += 1
        if group_unknown and len(unknown_dois) > 0:
            corpus_count += 1
            unk_ele_count = unk_size = 0
            for key in unknown_dois:
                corpus = AS3Bucket.get_corpus(key)
                unk_ele_count += corpus.get_element_count()
                unk_size += corpus.get_total_size()
            print 'Unknown: {} items totalling {}.'.format(unk_ele_count,
                                                           sizeof_fmt(unk_size))

        print 'Bucket: {}, holds {} corpora, '.format(bucket_name,
                                                      corpus_count) + \
              '{} items totalling {}.'.format(element_count,
                                              sizeof_fmt(total_size))

class FormatAnalyser(object):
    """ Analyses file formats and creates JSON report data. """

    @classmethod
    def analyse_bucket_mimes(cls, tool_name):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        element_count = total_size = 0
        formats = collections.defaultdict(dict)
        for key in AS3Bucket.get_corpus_keys():
            corpus = AS3Bucket.get_corpus(key)
            for etag in corpus.elements.keys():
                item, element = corpus.get_pair(etag)
                element_count += 1
                total_size += item.size
                result_set = ResultRegistry.results_for_sha1(item.sha1)
                result = result_set.get(tool_name)
                mime_res = result.get_mime_result()
                mime = '/'.join([mime_res.type, mime_res.subtype])
                sizes = formats.get(str(mime), None)
                if sizes is None:
                    sizes = []
                sizes.append(item.size)
                formats.update({str(mime) : sizes})
        for mime_type in formats.keys():
            sizes = formats.get(mime_type)
            print '{},{}'.format(mime_type, len(sizes))
        # print '{} items totalling {}'.format(element_count, sizeof_fmt(total_size))
        # print 'Max size {}, min size {}'.format(sizeof_fmt(max(sizes)),
        #                                         sizeof_fmt(min(sizes)))
        # for num in range(0, 11):
        #     result = sizeof_fmt(percentile(sizes, num * 10))
        #     print '{:d} percentile : {}'.format(num * 10, result)

class SizeAnalyser(object):
    """ Analyses file sizes and creates JSON report data. """

    @classmethod
    def analyse_bucket(cls):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        element_count = total_size = 0
        sizes = []
        for key in AS3Bucket.get_corpus_keys():
            corpus = AS3Bucket.get_corpus(key)
            for etag in corpus.elements.keys():
                item, element = corpus.get_pair(etag)
                element_count += 1
                total_size += item.size
                sizes.append(item.size)
        print '{} items totalling {}'.format(element_count, sizeof_fmt(total_size))
        print 'Max size {}, min size {}'.format(sizeof_fmt(max(sizes)),
                                                sizeof_fmt(min(sizes)))
        for num in range(0, 11):
            result = sizeof_fmt(percentile(sizes, num * 10))
            print '{:d} percentile : {}'.format(num * 10, result)

    @classmethod
    def analyse_blobstore(cls):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        print BlobStore.get_blob_count()
        print sizeof_fmt(BlobStore.get_total_blob_size())
        sizes = []
        for path in BlobStore.BLOBS.keys():
            size = BlobStore.get_blob(path).byte_sequence.size
            sizes.append(size)
        print 'Max size {}, min size {}'.format(max(sizes), min(sizes))
        for num in range(0, 11):
            result = sizeof_fmt(percentile(sizes, num * 10))
            print '{:d} percentile : {}'.format(num * 10, result)

def percentile(data, centile):
    array = np.array(data, dtype=int)
    return np.percentile(array, centile)

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
    parser.add_argument('-a', '--analyse', default=False, action='store_true',
                        help='analyse the blobstore and or corpus')
    parser.add_argument('-l', '--list', default=False, action='store_true',
                        help='list the names of known blobstores and corpora')
    parser.add_argument('--list-corpora', default=False, action='store_true',
                        help='list the names of known blobstores and corpora')
    parser.add_argument('--list-blobstores', default=False, action='store_true',
                        help='list the names of known blobstores and corpora')
    parser.add_argument('-c', '--corpus', default=None,
                        help='name of corpus to analyse')
    parser.add_argument('-b', '--blobstore', default=DEFAULTS['blobstore'],
                        help='name of blobstore to analyse')
    parser.add_argument('--bucket', default=DEFAULTS['bucket'],
                        help='name of bucket to analyse')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    version_header = "RDSS Format Analyser v{0}\n".format(__version__)

    if args.version:
        sys.stdout.write(version_header)
        sys.exit(0)

    if args.analyse:
        # BlobStore.initialise(args.blobstore, persist=True)
        # SizeAnalyser.analyse_blobstore()
        bucket_name = args.bucket
        bucket_exists, bucket = get_s3_bucket_by_name(bucket_name)
        if not bucket_exists:
            sys.exit('No AS3 bucket called {} found.'.format(bucket_name))
        AS3Bucket.initialise(bucket, persist=True)
        # BucketAnalyser.summarise(bucket_name, group_unknown=True)
        # SizeAnalyser.analyse_bucket()
        ResultRegistry.initialise(persist=True)
        FormatAnalyser.analyse_bucket_mimes('droid')
if __name__ == "__main__":
    main()
