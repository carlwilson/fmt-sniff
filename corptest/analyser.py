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

from corptest.blobstore import BlobStore
from corptest.const import EPILOG, JISC_BUCKET, BLOB_STORE_ROOT
from corptest.doi import DataciteDoiLookup
from corptest.registries import ResultRegistry, ToolRegistry
from corptest.s3_corpora import AS3Bucket
from corptest.utilities import sizeof_fmt

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
    def summarise_bucket(cls, bucket_name, group_unknown=True, include_json=False):
        """Create bucket summary, number of corpora, number and size of contents."""
        corpus_count = element_count = total_size = 0
        unknown_dois = []
        for corpus in AS3Bucket.get_corpora():
            datacentre = DataciteDoiLookup.lookup_by_doi(corpus.datacentre.doi)
            if group_unknown and datacentre.name == 'Unknown':
                unknown_dois.append(datacentre.doi)
                continue
            corp_elements, corp_size = cls.total_corpus(corpus, include_json)
            print('DOI: {}, Name: {}, '.format(datacentre.doi,
                                               datacentre.name) + \
                  '{} items totalling {}.'.format(corp_elements,
                                                  sizeof_fmt(corp_size)))
            corpus_count += 1
            element_count += corp_elements
            total_size += corp_size

        if len(unknown_dois) > 0:
            corpus_count += 1
            unk_ele_count = unk_size = 0
            for key in unknown_dois:
                corpus = AS3Bucket.get_corpus(key)
                corp_elements, corp_size = cls.total_corpus(corpus, include_json)
                unk_ele_count += corp_elements
                unk_size += corp_size
            element_count += unk_ele_count
            total_size += unk_size

            print('Unknown: {} items totalling {}.'.format(unk_ele_count,
                                                           sizeof_fmt(unk_size)))

        print('Bucket: {}, holds {} corpora, '.format(bucket_name,
                                                      corpus_count) + \
              '{} items totalling {}.'.format(element_count,
                                              sizeof_fmt(total_size)))

    @classmethod
    def total_corpus(cls, corpus, include_json=False):
        """Returns the total size of items in a corpus."""
        elements = size = 0
        for item in corpus.corpus.get_items(include_json=include_json):
            elements += 1
            size += item.size
        return elements, size

class FormatAnalyser(object):
    """ Analyses file formats and creates JSON report data. """

    @classmethod
    def analyse_bucket_mimes(cls, tool_name, include_json=False):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        element_count = total_size = 0
        formats = collections.defaultdict(dict)
        for corpus in AS3Bucket.get_corpora():
            for item in corpus.corpus.get_items(include_json=include_json):
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
            print('{},{}'.format(mime_type, len(sizes)))
        print('{} items totalling {}'.format(element_count, sizeof_fmt(total_size)))
        print('Max size {}, min size {}'.format(sizeof_fmt(max(sizes)),
                                                sizeof_fmt(min(sizes))))
        for num in range(0, 11):
            result = sizeof_fmt(percentile(sizes, num * 10))
            print('{:d} percentile : {}'.format(num * 10, result))

    @classmethod
    def compare_bucket_mimes(cls, tool_names=None, include_json=False):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        if tool_names is None:
            tool_names = ToolRegistry.TOOLS.keys()
        element_count = total_size = 0
        formats = collections.defaultdict(dict)
        for corpus in AS3Bucket.get_corpora():
            for item, element in corpus.get_pairs(include_json=include_json):
                element_count += 1
                total_size += item.size
                result_set = ResultRegistry.results_for_sha1(item.sha1)
                s3_mime = element.content_type
                cls.update_mime_sizes(s3_mime, 's3', formats, item.size)
                for tool_name in result_set.keys():
                    result = result_set.get(tool_name)
                    mime_res = result.get_mime_result()
                    mime = '/'.join([mime_res.type, mime_res.subtype])
                    cls.update_mime_sizes(mime, tool_name, formats, item.size)
        tools = ['s3']
        for tool_name in tool_names:
            tools.append(tool_name)
        print(','.join(tools))
        for mime_type in formats.keys():
            counts = []
            tool_results = formats.get(mime_type)
            for tool_name in tool_names:
                sizes = tool_results.get(tool_name, [])
                counts.append(str(len(sizes)))
            print('{},{}'.format(mime_type, ','.join(counts)))
        print('{} items totalling {}'.format(element_count, sizeof_fmt(total_size)))
        print('"MIME", "Max Size", "Min Size", "Average Size"')
        for mime_type in formats.keys():
            tool_results = formats.get(mime_type)
            sizes = tool_results.get('file', [])
            if len(sizes) > 0:
                print('{},{},{},{}'.format(mime_type,
                                           sizeof_fmt(max(sizes)),
                                           sizeof_fmt(min(sizes)),
                                           sizeof_fmt(sum(sizes)/len(sizes))))
        centile_titles = []
        for num in range(0, 11):
            centile_titles.append(str(num * 10))
        print('"MIME", {}'.format(','.join(centile_titles)))
        for mime_type in formats.keys():
            tool_results = formats.get(mime_type)
            sizes = tool_results.get('file', [])
            if len(sizes) > 0:
                centiles = []
                for num in range(0, 11):
                    result = sizeof_fmt(percentile(sizes, num * 10))
                    centiles.append(str(result))
                print('{},{}'.format(mime_type, ','.join(centiles)))

    @classmethod
    def compare_bucket_puids(cls, tool_names=None, include_json=False):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        if tool_names is None:
            tool_names = ['fido', 'droid']
        element_count = total_size = 0
        formats = collections.defaultdict(dict)
        names = collections.defaultdict(dict)
        for corpus in AS3Bucket.get_corpora():
            for item in corpus.corpus.get_items(include_json=include_json):
                element_count += 1
                total_size += item.size
                result_set = ResultRegistry.results_for_sha1(item.sha1)
                for tool_name in result_set.keys():
                    result = result_set.get(tool_name)
                    puid = result.get_pronom_result()
                    names.update({puid.puid : puid.sig})
                    cls.update_mime_sizes(puid.puid, tool_name, formats, item.size)
        tools = []
        for tool_name in tool_names:
            tools.append(tool_name)
        print(','.join(tools))
        for puid in formats.keys():
            counts = []
            tool_results = formats.get(puid)
            for tool_name in tools:
                sizes = tool_results.get(tool_name, [])
                counts.append(str(len(sizes)))
            print('"{}", "{}", {}'.format(puid, names.get(puid), ','.join(counts)))
        print('{} items totalling {}'.format(element_count, sizeof_fmt(total_size)))
        for puid in formats.keys():
            tool_results = formats.get(puid)
            sizes = tool_results.get('droid', [])
            if len(sizes) > 0:
                print('PUID {} : Max size {}, min size {}'.format(puid,
                                                                  sizeof_fmt(max(sizes)),
                                                                  sizeof_fmt(min(sizes))))
                centile_titles = []
                centiles = []
                for num in range(0, 11):
                    result = sizeof_fmt(percentile(sizes, num * 10))
                    centile_titles.append(str(num * 10))
                    centiles.append(str(result))
                print(','.join(centile_titles))
                print(','.join(centiles))

    @staticmethod
    def update_mime_sizes(mime_string, tool_name, formats, item_size):
        """ Updates the size entry for a particular MIME string."""
        tool_results = formats.get(mime_string, None)
        if tool_results is None:
            tool_results = collections.defaultdict(dict)
        sizes = tool_results.get(tool_name)
        if sizes is None:
            sizes = []
        sizes.append(item_size)
        tool_results.update({tool_name : sizes})
        formats.update({mime_string : tool_results})


class SizeAnalyser(object):
    """ Analyses file sizes and creates JSON report data. """

    @classmethod
    def analyse_bucket(cls, include_json=False):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        element_count = total_size = 0
        sizes = []
        for corpus in AS3Bucket.get_corpora():
            for item in corpus.corpus.get_items(include_json=include_json):
                element_count += 1
                total_size += item.size
                sizes.append(item.size)
        print('{} items totalling {}'.format(element_count, sizeof_fmt(total_size)))
        print('Max size {}, min size {}'.format(sizeof_fmt(max(sizes)),
                                                sizeof_fmt(min(sizes))))
        for num in range(0, 11):
            result = sizeof_fmt(percentile(sizes, num * 10))
            print('{:d} percentile : {}'.format(num * 10, result))

    @classmethod
    def analyse_blobstore(cls):
        """Create JSON report for a Corpus, reports:
        - Number of items
        - distribution of 10 percentiles of file sizes
        """
        print(BlobStore.get_blob_count())
        print(sizeof_fmt(BlobStore.get_total_blob_size()))
        sizes = []
        for path in BlobStore.BLOBS.keys():
            size = BlobStore.get_blob(path).byte_sequence.size
            sizes.append(size)
        print('Max size {}, min size {}'.format(max(sizes), min(sizes)))
        for num in range(0, 11):
            result = sizeof_fmt(percentile(sizes, num * 10))
            print('{:d} percentile : {}'.format(num * 10, result))

def percentile(data, centile):
    """ Calc the percentiles centile from a Python list using numpy. """
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
    parser.add_argument('-g', '--group', default=True, action='store_true',
                        help='groups unknown institituions together')
    parser.add_argument('-l', '--list', default=False, action='store_true',
                        help='list the names of known blobstores and corpora')
    parser.add_argument('--listcorpora', default=False, action='store_true',
                        help='list the names of known corpora')
    parser.add_argument('--listblobstores', default=False, action='store_true',
                        help='list the names of known blobstores')
    parser.add_argument('-c', '--corpus', default=None,
                        help='name of corpus to analyse')
    parser.add_argument('-b', '--blobstore', default=DEFAULTS['blobstore'],
                        help='name of blobstore to analyse')
    parser.add_argument('--bucket', default=DEFAULTS['bucket'],
                        help='name of bucket to analyse')
    parser.add_argument('--json', default=False, action='store_true',
                        help='include JSON data in analysis')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    version_header = "RDSS Format Analyser v{0}\n".format(__version__)

    if args.version:
        sys.stdout.write(version_header)
        sys.exit(0)

    bucket_name = args.bucket
    bucket_exists, bucket = get_s3_bucket_by_name(bucket_name)
    if not bucket_exists:
        sys.exit('No AS3 bucket called {} found.'.format(bucket_name))
    AS3Bucket.initialise(bucket, persist=True)
    DataciteDoiLookup.initialise()

    if args.list or args.listcorpora:
        for corpus in AS3Bucket.get_corpora():
            print('{} : {}'.format(corpus.datacentre.doi, corpus.datacentre.name))

    if args.analyse:
        BlobStore.initialise(args.blobstore, persist=True)
        BucketAnalyser.summarise_bucket(bucket_name, include_json=args.json,
                                        group_unknown=args.group)
        SizeAnalyser.analyse_bucket(include_json=args.json)
        ResultRegistry.initialise(persist=True)
        ToolRegistry.initialise(persist=True)
        FormatAnalyser.compare_bucket_mimes(include_json=args.json)
        FormatAnalyser.compare_bucket_puids(include_json=args.json)

if __name__ == "__main__":
    main()
