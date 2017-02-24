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
""" Current driver of command line app. """
from argparse import ArgumentParser, RawTextHelpFormatter
import sys

from const import JISC_BUCKET, EPILOG
from s3_corpora import get_s3_bucket_by_name, AS3Bucket
from registries import ResultRegistry

from . import __version__

DEFAULTS = {
    'bucket': JISC_BUCKET,
    'description': """JISC Research Data Shared Service (RDSS) Format Identification
Toolset. JISCRDSS Python tools to test format identification tools across test corpora,
primarily held on Amazon S3 storage.""",
    'epilog': EPILOG,
}

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
    parser.add_argument('-t', '--test', default=False, action='store_true',
                        help='test corpus at bucket filtered by doi')
    parser.add_argument('-b', '--bucket', default=DEFAULTS['bucket'],
                        help='name of a bucket to use as corpus root')
    parser.add_argument('--doi', default=None,
                        help='doi of institution to filter tests')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)

    version_header = "Corpus Test v{0}\n".format(__version__)

    if args.version:
        sys.stdout.write(version_header)
        sys.exit(0)

    if args.test:
        bucket_name = args.bucket
        bucket_exists, bucket = get_s3_bucket_by_name(bucket_name)
        if not bucket_exists:
            sys.exit('No AS3 bucket called {} found.'.format(bucket_name))
        AS3Bucket.initialise(bucket, persist=True)

    for corpus in AS3Bucket.get_corpora():
        print '{} : {}, {} items, {} bytes.'.format(corpus.datacentre.doi,
                                                    corpus.datacentre.name,
                                                    corpus.get_element_count(),
                                                    corpus.get_total_size())

    ResultRegistry.initialise(persist=True)
    print '{} results.'.format(len(ResultRegistry.RESULTS))

#    print "Preparing report"
#    reporter = CorpusReporter.corpus_report(corpus, blobstore)
#    print "Rendering report"
#    reporter.render_report()

if __name__ == "__main__":
    main()
