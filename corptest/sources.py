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
import logging
import os.path
from os import access, R_OK, stat

try:
    from os import scandir
except ImportError:
    from scandir import scandir as scandir

import re
import tempfile

from botocore import exceptions
from boto3 import client, resource

from tzlocal import get_localzone

from .corptest import APP
from .blobstore import Sha1Lookup, BlobStore
from .format_tools import FormatToolRelease, get_format_tool_instance
from .model_sources import ByteSequence
from .model_properties import Property, PropertyValue
from .utilities import sha1_path, timestamp_fmt, Extension

RDSS_ROOT = APP.config.get('RDSS_ROOT')
BLOB_STORE_ROOT = os.path.join(RDSS_ROOT, 'blobstore')

Sha1Lookup.initialise()
BLOBSTORE = BlobStore(BLOB_STORE_ROOT)

class SourceKey(object):
    """Simple class encapsulating 2 parts of a key, the value and whether it's a folder."""

    def __init__(self, value, is_folder=True, size=0, last_modified=datetime.now()):
        if value is None:
            raise ValueError("Argument value can not be None.")
        if size is None:
            raise ValueError("Argument size can not be None.")
        if size < 0:
            raise ValueError("Argument size can not be less than zero")
        self.__value = value
        self.__is_folder = is_folder
        self.__size = size
        self.__last_modified = last_modified
        self.__properties = collections.defaultdict()

    @property
    def value(self):
        """ Return the key value, it's unique path. """
        return self.__value

    @property
    def is_folder(self):
        """ Return true if key is that of a file item. """
        return self.__is_folder

    @property
    def name(self):
        """Return the name of the item without the path."""
        parts = self.value.split('/')
        return parts[-2] if self.value.endswith('/') else parts[-1]

    @property
    def extension(self):
        """Resturn the extension part of the key value."""
        _ext = Extension.parse_from_file_name(self.value)
        return _ext if _ext else ''

    @property
    def size(self):
        """ Return the key size in bytes or empty string. """
        return self.__size if not self.is_folder else 0

    @property
    def last_mod(self):
        """ Return the last modified date as a datetime stamp. """
        return self.__last_modified

    @property
    def properties(self):
        """ Return the set of the keys known properties. """
        return self.__properties

    @property
    def last_modified(self):
        """ Return the last modified date as a String. """
        return timestamp_fmt(self.__last_modified) if not self.is_folder else 'n/a'

    @property
    def parts(self):
        """Split a path into parts and return tuples of part name and full part path."""
        part_path = ''
        for part in self.value.split('/'):
            yield part, '/'.join([part_path, part]) if part_path else part
            part_path = '/'.join([part_path, part]) if part_path else part

    def add_properties(self, prop_dict):
        """Add the key value pairs in prop_dict to this."""
        if prop_dict is None:
            raise ValueError("Argument prop_dict can not be None.")
        self.__properties.update(prop_dict)

    def add_property(self, key, value):
        """Add the Property to_append to this keys list of properties."""
        if key is None:
            raise ValueError("Argument key can not be None.")
        if value is None:
            raise ValueError("Argument value can not be None.")
        self.__properties[key] = value

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

    def __str__(self):
        return self.__rep__()

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.sources.SourceKey : [value=")
        ret_val.append(self.value)
        ret_val.append(", extension=")
        ret_val.append(self.extension)
        ret_val.append(", is_folder=")
        ret_val.append(str(self.is_folder))
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append(", last_modified=")
        ret_val.append(self.last_modified)
        ret_val.append("]")

        return "".join(ret_val)

PYTHON_NAMESPACE = 'os.python.org'
class SourceBase(object):
    """Base class for different sources."""
    __metaclass__ = abc.ABCMeta
    PYTHON_NAMESPACE = PYTHON_NAMESPACE

    @abc.abstractmethod
    def namespace(self): # pragma: no cover
        """Returns the source's namespace as a String."""
        return

    @abc.abstractmethod
    def supported_properties(self): # pragma: no cover
        """Returns the set of properties supported by the source."""
        return

    @abc.abstractmethod
    def all_file_keys(self): # pragma: no cover
        """Generator that returns all file keys for a source."""
        return

    @abc.abstractmethod
    def key_exists(self, key): # pragma: no cover
        """Check to see if a key exists, returns true if it does, false otherwise."""
        return

    @abc.abstractmethod
    def get_key(self, path): # pragma: no cover
        """ Get the basic key details for a path."""
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
    def get_key_properties(self, key):
        """Takes a key and augments it with detailed metadata about a File
        element. Throws a ValueError if a folder key is passed."""
        return

    @abc.abstractmethod
    def get_path_and_byte_seq(self, key, sha1):
        """ Returns a file path and ByteSequence tuple for the key. """
        return

    @staticmethod
    def _validate_key_and_return_prefix(filter_key):
        prefix = ''
        if filter_key is not None:
            if not filter_key.is_folder:
                raise ValueError("Argument filter_key must be a folder key.")
            prefix = filter_key.value
        return prefix

    @staticmethod
    def _prop_vals_from_dict(props_dict):
        logging.debug('Checking dict %s', props_dict)
        ret_val = set([])
        if isinstance(props_dict, dict):
            for _md_key in props_dict:
                prop_val = PropertyValue.putdate(props_dict[_md_key])
                ret_val.add(prop_val)
        else:
            raise ValueError("Argument props_dict must be a dict type.")
        return ret_val

    @staticmethod
    def _create_properties_from_names(names, namespace=PYTHON_NAMESPACE):
        ret_val = collections.defaultdict()
        for name in names:
            prop = Property(namespace, name)
            ret_val[name] = prop
        return ret_val

class AS3Bucket(SourceBase):
    """A Source based on an Amazon S3 bucket."""
    NAMESPACE = 's3.amazon.com'
    FOLDER_REGEX = re.compile('.*/$')
    S3_RESOURCE = None
    ETAG = 'ETag'
    CONT_TYPE = 'ContentType'
    CONT_ENC = 'ContentEncoding'

    __PROPERTIES = SourceBase._create_properties_from_names(set([ETAG, CONT_TYPE, CONT_ENC]),
                                                            namespace=NAMESPACE)

    def __init__(self, bucket):
        if not bucket:
            raise ValueError("Argument bucket can not be None.")
        bucket_exists = self.validate_bucket(bucket.location)
        if not bucket_exists:
            raise ValueError('No AS3 bucket called {} found.'.format(bucket.location))
        self.__bucket = bucket

    @property
    def namespace(self):
        return self.NAMESPACE

    @property
    def bucket(self):
        """Return the Amazon S3 bucket."""
        return self.__bucket

    @property
    def supported_properties(self): # pragma: no cover
        return self.__PROPERTIES

    def key_exists(self, key):
        key = key if key else SourceKey('/')
        s3_client = client('s3')
        if key.is_folder:
            prefix = super(AS3Bucket, self)._validate_key_and_return_prefix(key)
            if prefix and not prefix.endswith('/'):
                prefix += '/'
            result = s3_client.list_objects_v2(Bucket=self.bucket.location,
                                               Prefix=prefix, Delimiter='/')
            if not result.get('CommonPrefixes'):
                if not result.get('Contents'):
                    return False
        else:
            try:
                s3_client.head_object(Bucket=self.bucket.location, Key=key.value)
            except exceptions.ClientError:
                return False
        return True

    def get_key(self, path): # pragma: no cover
        """ Get the basic key details for a path."""
        result = self._get_object_result(path)
        key = SourceKey(path, False, result.get('ContentLength'),
                        result.get('LastModified'))
        properties = self._get_s3_properties_from_result(key, result)
        key.add_properties(properties)
        return key

    def all_file_keys(self):
        bucket = self.S3_RESOURCE.Bucket(self.bucket.location)
        for obj_summary in bucket.objects.all():
            if self.FOLDER_REGEX.match(obj_summary.key) is None:
                yield SourceKey(obj_summary.key, False)

    def list_folders(self, filter_key=None, recurse=False):
        prefix = super(AS3Bucket, self)._validate_key_and_return_prefix(filter_key)
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        s3_client = client('s3')
        result = s3_client.list_objects_v2(Bucket=self.bucket.location,
                                           Prefix=prefix, Delimiter='/')
        if result.get('CommonPrefixes'):
            for common_prefix in result.get('CommonPrefixes'):
                yield SourceKey(common_prefix.get('Prefix'))
                if recurse:
                    key = SourceKey(common_prefix.get('Prefix'))
                    for res in self.list_folders(filter_key=key, recurse=True):
                        yield res

    def list_files(self, filter_key=None, recurse=False):
        prefix = super(AS3Bucket, self)._validate_key_and_return_prefix(filter_key)
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        s3_client = client('s3')
        result = s3_client.list_objects_v2(Bucket=self.bucket.location,
                                           Prefix=prefix, Delimiter='/')
        if result.get('Contents'):
            for obj_summary in result.get('Contents'):
                key = SourceKey(obj_summary.get('Key'), False, obj_summary.get('Size'),
                                obj_summary.get('LastModified'))
                key.add_property(self.__PROPERTIES[self.ETAG], self._etag_from_result(obj_summary))
                yield key
        if recurse:
            if result.get('CommonPrefixes'):
                for common_prefix in result.get('CommonPrefixes'):
                    key = SourceKey(common_prefix.get('Prefix'))
                    for res in self.list_files(filter_key=key, recurse=True):
                        yield res

    def get_byte_sequence_properties(self, key):
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        logging.info("Obtaining meta for key: %s, value: %s", key, key.value)
        props = self.get_key_properties(key)
        full_path, _bs = self.get_path_and_byte_seq(key)
        props['SHA1'] = _bs.sha1
        for tool_release in FormatToolRelease.get_enabled():
            logging.debug("Checking %s", tool_release.format_tool.name)
            tool = get_format_tool_instance(tool_release.format_tool)
            if tool.version:
                logging.debug("Invoking %s", tool.format_tool_release.format_tool.name)
                metadata = tool.identify(full_path)
                if metadata:
                    props.update(metadata)
        return _bs, props

    def _get_object_result(self, key_value):
        s3_client = client('s3')
        return s3_client.get_object(Bucket=self.bucket.location, Key=key_value)

    def get_key_properties(self, key):
        if key.is_folder:
            raise ValueError("Argument key %s can't be a folder" % key.value)
        result = self._get_object_result(key.value)
        props = self._get_s3_properties_from_result(key, result)
        for md_key, md_value in result['Metadata']:
            props[md_key] = md_value
        return props

    @classmethod
    def _get_s3_properties_from_result(cls, key, result):
        """Get the S3 properties for a key."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        props = collections.defaultdict()

        logging.info("Obtaining S3 meta for key: %r", key)
        props[cls.ETAG] = result.get(cls.ETAG)[1:-1]
        props[cls.CONT_TYPE] = result.get(cls.CONT_TYPE)
        props[cls.CONT_ENC] = result.get(cls.CONT_ENC)
        return props

    def get_path_and_byte_seq(self, key, sha1=None):
        """Creates a temp file copy of a file from the specified image."""
        if not key or key.is_folder:
            # File keys only please
            raise ValueError("Argument key must be a file key.")
        etag = key.properties[self.ETAG]
        if not etag:
            etag = self.get_key_properties(key)[self.ETAG]
        if sha1 is None:
            sha1 = Sha1Lookup.get_sha1(etag)
        # Check if we know the SHA1, if we do and the Blobstore has a copy use that
        if sha1 and BLOBSTORE.has_copy(sha1):
            logging.info('SHA1 %s is cached in local BlobStore, using as temp', sha1)
        else:
            # No locally cached version so retrieve from S3 to a temp file
            logging.info("No locally cached copy so downloading from S3.")
            s3_client = client('s3')
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                s3_client.download_fileobj(self.bucket.location, key.value, temp)
                sha1 = sha1_path(temp.name)
                BLOBSTORE.add_file(temp.name, sha1)
        byte_seq = ByteSequence.by_sha1(sha1)
        file_path = BLOBSTORE.get_blob_path(sha1)
        if byte_seq is None:
            byte_seq = ByteSequence(sha1, os.path.getsize(file_path))
            byte_seq.put()
        return file_path, byte_seq

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

    @classmethod
    def _etag_from_result(cls, result):
        return result.get(cls.ETAG)[1:-1]

class FileSystem(SourceBase):
    """A source based on a file system"""
    TIME_ZONE = get_localzone()
    CREATED = 'Created'
    ACCESSED = 'LastAccessed'
    __PROPERTIES = SourceBase._create_properties_from_names(set([CREATED, ACCESSED]))

    def __init__(self, file_system):
        if not file_system:
            raise ValueError("Argument file_system can not be None.")
        if not os.path.isdir(file_system.location) or not access(file_system.location, R_OK):
            raise ValueError("Argument file_system.location %s must be an existing dir" % \
                             file_system.location)
        self.__file_system = file_system

    @property
    def namespace(self):
        return super(FileSystem, self).PYTHON_NAMESPACE

    @property
    def file_system(self):
        """Return the file system model entitiy for this corpus."""
        return self.__file_system

    def get_key(self, path): # pragma: no cover
        """ Get the basic key details for a path."""
        result = stat(os.path.join(self.file_system.location, path))
        key = SourceKey(path, False,
                        int(result.st_size),
                        datetime.fromtimestamp(result.st_mtime, self.TIME_ZONE))
        properties = self.get_fs_metadata_from_result(key, result)
        key.add_properties(properties)
        return key

    def key_exists(self, key): # pragma: no cover
        check_val = key.value if key else ''
        full_path = os.path.join(self.file_system.location, check_val)
        return os.path.exists(full_path)

    @property
    def supported_properties(self): # pragma: no cover
        return self.__PROPERTIES

    def all_file_keys(self):
        return self.list_files(recurse=True)

    def list_folders(self, filter_key=None, recurse=False):
        prefix = super(FileSystem, self)._validate_key_and_return_prefix(filter_key)
        return self.yield_keys(prefix, list_files=False, recurse=recurse)

    def list_files(self, filter_key=None, recurse=False):
        prefix = super(FileSystem, self)._validate_key_and_return_prefix(filter_key)
        return self.yield_keys(prefix, list_folders=False, recurse=recurse)

    def yield_keys(self, prefix='', list_files=True, list_folders=True, recurse=False):
        """Generator that yields a list of file and or folder keys from a root
        directory."""
        path = os.path.join(self.file_system.location, prefix)
        if os.access(path, os.R_OK):
            for entry in scandir(os.path.join(self.file_system.location, prefix)):
                if list_files and entry.is_file(follow_symlinks=False):
                    key = SourceKey(os.path.join(prefix, entry.name), False,
                                    int(entry.stat().st_size),
                                    datetime.fromtimestamp(entry.stat().st_mtime, self.TIME_ZONE))

                    yield key

                if entry.is_dir(follow_symlinks=False):
                    if list_folders:
                        yield SourceKey(os.path.join(prefix, entry.name))
                    if recurse:
                        for child in self.yield_keys(prefix=os.path.join(prefix, entry.name),
                                                     list_files=list_files,
                                                     list_folders=list_folders,
                                                     recurse=True):
                            yield child

    def get_byte_sequence_properties(self, key):
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        path, _bs = self.get_path_and_byte_seq(key)
        full_path = os.path.join(self.file_system.location, path)
        result = stat(full_path)
        props = collections.defaultdict()
        props.update(self.get_fs_metadata_from_result(key, result))
        sha1 = sha1_path(full_path)
        props['SHA1'] = sha1 if sha1 else ''

        for tool_release in FormatToolRelease.get_enabled():
            tool = get_format_tool_instance(tool_release.format_tool)
            logging.debug("Checking %s", tool.format_tool_release.format_tool.name)
            if tool.version:
                logging.debug("Invoking %s", tool.format_tool_release.format_tool.name)
                metadata = tool.identify(full_path)
                if metadata:
                    props.update(metadata)
        return _bs, props

    @classmethod
    def get_fs_metadata_from_result(cls, key, result):
        """Get the fs Metadata types for a key."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        logging.info("Obtaining FS meta for key: %s", key)
        metadata = collections.defaultdict(dict)
        metadata[cls.CREATED] = datetime.fromtimestamp(result.st_ctime,
                                                       cls.TIME_ZONE)
        metadata[cls.ACCESSED] = datetime.fromtimestamp(result.st_atime,
                                                        cls.TIME_ZONE)
        return metadata

    def get_key_properties(self, key):
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        full_path = os.path.join(self.file_system.location, key.value)
        result = stat(full_path)
        properties = self.get_fs_metadata_from_result(key, result)
        return properties

    def get_path_and_byte_seq(self, key, sha1=None):
        """Creates a temp file copy of a file from the specified image."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        file_path = os.path.join(self.file_system.location, key.value)

        sha1 = sha1_path(file_path) if os.access(file_path, R_OK) else ByteSequence.EMPTY_SHA1
        byte_seq = ByteSequence.by_sha1(sha1)
        if byte_seq is None:
            byte_seq = ByteSequence(sha1, os.path.getsize(file_path))
            byte_seq.put()
        return file_path, byte_seq

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.sources.FileSystem : [FileSystemSource=")
        ret_val.append(str(self.file_system))
        ret_val.append("]")
        return "".join(ret_val)
