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
"""
Classes that encapsulate different sources of data to be identified.
"""
import abc
import collections
from datetime import datetime

from os import access, path, R_OK, stat
try:
    from os import scandir
except ImportError:
    from scandir import scandir as scandir

import re
import tempfile

from botocore import exceptions
from boto3 import client, resource

from tzlocal import get_localzone

from corptest import APP
from corptest.blobstore import Sha1Lookup, BlobStore
from corptest.formats import MimeType
from corptest.utilities import sha1_path, timestamp_fmt

RDSS_ROOT = APP.config.get('RDSS_ROOT')
BLOB_STORE_ROOT = path.join(RDSS_ROOT, 'blobstore')

Sha1Lookup.initialise()
BLOBSTORE = BlobStore(BLOB_STORE_ROOT)

class SourceKey(object):
    """Simple class encapsulating 2 parts of a key, the value and whether it's a folder."""

    def __init__(self, value, is_folder=True, size=0, last_modified=datetime.now()):
        if not value:
            raise ValueError("Argument value can not be None or an empty string.")
        self.__value = value
        self.__is_folder = is_folder
        self.__size = size
        self.__last_modified = last_modified
        self.__metadata = collections.defaultdict(dict)

    @property
    def value(self):
        """ Return the key value, it's unique path. """
        return self.__value

    @property
    def is_folder(self):
        """ Return true if key is that of a file item. """
        return self.__is_folder

    @property
    def size(self):
        """ Return the key size in bytes or empty string. """
        return str(self.__size) if not self.is_folder else 'n/a'

    @property
    def parts(self):
        """Split a path into parts and return tuples of part name and full part path."""
        part_path = ''
        for part in self.value.split('/'):
            yield part, '/'.join([part_path, part]) if part_path else part
            part_path = '/'.join([part_path, part]) if part_path else part

    @property
    def name(self):
        """Return the name of the item without the path."""
        parts = self.value.split('/')
        return parts[-2 if self.is_folder and len(parts) > 1 else -1]

    @property
    def last_modified(self):
        """ Return the key size in bytes or empty string. """
        return timestamp_fmt(self.__last_modified) if not self.is_folder else 'n/a'

    @property
    def metadata(self):
        """ Return the metadata dictionary object. """
        return self.__metadata

    @metadata.setter
    def metadata(self, key, value):
        self.__metadata.update({key: value})

    def __key(self):
        return (self.value, self.is_folder)

    def __eq__(self, other):
        """ Define an equality test for ByteSequence """
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        """ Define an inequality test for ByteSequence """
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.sources.SourceKey : [value=")
        ret_val.append(self.value)
        ret_val.append(", is_folder=")
        ret_val.append(str(self.is_folder))
        ret_val.append("]")
        return "".join(ret_val)

class SourceBase(object):
    """Abstract base class for Source classes."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def all_file_keys(self): # pragma: no cover
        """Generator that returns all file keys for a source."""
        return

    @abc.abstractmethod
    def metadata_keys(self): # pragma: no cover
        """Returns a list of metadata keys supported by the source."""
        return

    @abc.abstractmethod
    def list_folders(self, filter_key=None, recurse=False): # pragma: no cover
        """Generator that lists the keys for all folders that are children of
        filter_key which is a SourceKey instance and must be a folder. The
        method will recurse into children if recurse is True."""
        return

    @abc.abstractmethod
    def list_files(self, filter_key=None, recurse=False): # pragma: no cover
        """Generator that lists the keys for all files that are children of
        filter_key which is a SourceKey instance and must be a folder. The
        method will recurse into children if recurse is True."""
        return

    @abc.abstractmethod
    def get_file_metadata(self, key):
        """Takes a key and augments it with detailed metadata about a File
        element. Throws a ValueError if a folder key is passed."""
        return

    @abc.abstractstaticmethod
    def validate_key_and_return_prefix(filter_key):
        """Checks that filter key is a folder and throws a ValueError if it's a
        file. If filter_key is a folder then a search prefix based on the key is
        returned, or an empty string if filter_key is None."""
        prefix = ''
        if filter_key is not None:
            if not filter_key.is_folder:
                raise ValueError("Argument filter_key must be a folder key.")
            prefix = filter_key.value
        return prefix

class AS3Bucket(SourceBase):
    """A Source based on an Amazon S3 bucket."""
    FOLDER_REGEX = re.compile('.*/$')
    S3_RESOURCE = None
    __KEYS = ['ETag']
    def __init__(self, bucket):
        if not bucket:
            raise ValueError("Argument bucket can not be None.")
        bucket_exists = self.validate_bucket(bucket.bucket_name)
        if not bucket_exists:
            raise ValueError('No AS3 bucket called {} found.'.format(bucket.bucket_name))
        self.__bucket = bucket

    @property
    def bucket(self):
        """Return the Amazon S3 bucket."""
        return self.__bucket

    def metadata_keys(self): # pragma: no cover
        return self.__KEYS

    def all_file_keys(self):
        bucket = self.S3_RESOURCE.Bucket(self.bucket.bucket_name)
        for obj_summary in bucket.objects.all():
            if self.FOLDER_REGEX.match(obj_summary.key) is None:
                yield SourceKey(obj_summary.key, False)

    def list_folders(self, filter_key=None, recurse=False):
        prefix = super().validate_key_and_return_prefix(filter_key)
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        s3_client = client('s3')
        result = s3_client.list_objects_v2(Bucket=self.bucket.bucket_name,
                                           Prefix=prefix, Delimiter='/')
        if result.get('CommonPrefixes'):
            for common_prefix in result.get('CommonPrefixes'):
                yield SourceKey(common_prefix.get('Prefix'))
                if recurse:
                    key = SourceKey(common_prefix.get('Prefix'))
                    for res in self.list_folders(filter_key=key, recurse=True):
                        yield res

    def list_files(self, filter_key=None, recurse=False):
        prefix = super().validate_key_and_return_prefix(filter_key)
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        s3_client = client('s3')
        result = s3_client.list_objects_v2(Bucket=self.bucket.bucket_name,
                                           Prefix=prefix, Delimiter='/')
        if result.get('Contents'):
            for obj_summary in result.get('Contents'):
                key = SourceKey(obj_summary.get('Key'), False, obj_summary.get('Size'),
                                obj_summary.get('LastModified'))
                key.metadata['ETag'] = obj_summary.get('ETag')[1:-1]
                yield key
        if recurse:
            if result.get('CommonPrefixes'):
                for common_prefix in result.get('CommonPrefixes'):
                    key = SourceKey(common_prefix.get('Prefix'))
                    for res in self.list_files(filter_key=key, recurse=True):
                        yield res

    def get_file_metadata(self, key):
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        import logging
        logging.warning("getting S3 meta")
        s3_client = client('s3')
        result = s3_client.get_object(Bucket=self.bucket.bucket_name,
                                      Key=key.value)
        logging.warning("Augmenting key")
        augmented_key = SourceKey(key.value, False, result.get('ContentLength'),
                                  result.get('LastModified'))
        etag = result.get('ETag')[1:-1]
        augmented_key.metadata['ETag'] = etag
        augmented_key.metadata['ContentType'] = result.get('ContentType')
        augmented_key.metadata['ContentEncoding'] = result.get('ContentEncoding')
        for md_key, md_value in result['Metadata']:
            augmented_key.metadata[md_key] = md_value
        logging.warning("Obtaining SHA1")
        sha1 = Sha1Lookup.get_sha1(etag)
        logging.warning("Adding SHA1")
        augmented_key.metadata['SHA1'] = sha1 if sha1 else ''
        logging.warning("Sha1 is %s, identifying", sha1)
        if sha1:
            logging.warning("Sha1 is %s, identifying", sha1)
            full_path = BLOBSTORE.get_blob_path(sha1)
            logging.warning("full_path  %s, identifying", full_path)
            magic_mime = MimeType.from_file_by_magic(full_path)
            logging.warning("MIME is %s, identifying", magic_mime)
            augmented_key.metadata['Python lib-magic'] = magic_mime if magic_mime else ''
        return augmented_key

    def get_temp_file(self, key):
        """Creates a temp file copy of a file from the specified image."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        s3_client = client('s3')
        # Open with a named temp file
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            s3_client.download_fileobj(self.bucket.bucket_name, key.value, temp)
            sha1 = sha1_path(temp.name)
            return temp.name, sha1

    @classmethod
    def validate_bucket(cls, bucket_name):
        """Retrieve the bucket named bucket_name from the passed s3_resource and
        validate it could be found (no 404) before returning the bucket.
        """
        if not cls.S3_RESOURCE:
            cls.S3_RESOURCE = resource('s3')
        exists = True
        try:
            cls.S3_RESOURCE.meta.client.head_bucket(Bucket=bucket_name)
        except exceptions.ClientError as boto_excep:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = int(boto_excep.response['Error']['Code'])
            if error_code == 404:
                exists = False
        return exists

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.source.AS3Bucket: [AS3BucketSource=")
        ret_val.append(str(self.bucket))
        ret_val.append("]")
        return "".join(ret_val)

class FileSystem(SourceBase):
    """A source based on a file system"""
    TIME_ZONE = get_localzone()
    __KEYS = []

    def __init__(self, file_system):
        if not file_system:
            raise ValueError("Argument file_system can not be None.")
        if not path.isdir(file_system.root) or not access(file_system.root, R_OK):
            raise ValueError("Argument file_system.root must be an existing dir")
        self.__file_system = file_system

    @property
    def file_system(self):
        """Return the root path to the file system corpus."""
        return self.__file_system

    def metadata_keys(self): # pragma: no cover
        return self.__KEYS

    def all_file_keys(self):
        return self.list_files(recurse=True)

    def list_folders(self, filter_key=None, recurse=False):
        prefix = super().validate_key_and_return_prefix(filter_key)
        return self.yield_keys(prefix, list_files=False, recurse=recurse)

    def list_files(self, filter_key=None, recurse=False):
        prefix = super().validate_key_and_return_prefix(filter_key)
        return self.yield_keys(prefix, list_folders=False, recurse=recurse)

    def yield_keys(self, prefix='', list_files=True, list_folders=True, recurse=False):
        """Generator that yields a list of file and or folder keys from a root
        directory."""
        for entry in scandir(path.join(self.file_system.root, prefix)):
            if list_files and entry.is_file(follow_symlinks=False):
                yield SourceKey(path.join(prefix, entry.name), False, entry.stat().st_size,
                                datetime.fromtimestamp(entry.stat().st_mtime, self.TIME_ZONE))
            if entry.is_dir(follow_symlinks=False):
                if list_folders:
                    yield SourceKey(path.join(prefix, entry.name))
                if recurse:
                    for child in self.yield_keys(prefix=path.join(prefix, entry.name),
                                                 list_files=list_files,
                                                 list_folders=list_folders,
                                                 recurse=True):
                        yield child

    def get_file_metadata(self, key):
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        full_path = path.join(self.file_system.root, key.value)
        result = stat(full_path)
        augmented_key = SourceKey(key.value, False, result.st_size,
                                  datetime.fromtimestamp(result.st_mtime,
                                                         self.TIME_ZONE))
        sha1 = sha1_path(full_path)
        augmented_key.metadata['SHA1'] = sha1 if sha1 else ''
        augmented_key.metadata['Created'] = datetime.fromtimestamp(result.st_ctime,
                                                                   self.TIME_ZONE)
        augmented_key.metadata['LastAccessed'] = datetime.fromtimestamp(result.st_atime,
                                                                        self.TIME_ZONE)
        magic_mime = MimeType.from_file_by_magic(full_path)
        augmented_key.metadata['Python lib-magic'] = magic_mime if magic_mime else ''
        return augmented_key

    def get_temp_file(self, key):
        """Creates a temp file copy of a file from the specified image."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        file_path = path.join(self.file_system.root, key.value)
        sha1 = sha1_path(file_path)
        return file_path, sha1

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.sources.FileSystem : [FileSystemSource=")
        ret_val.append(str(self.file_system))
        ret_val.append("]")
        return "".join(ret_val)
