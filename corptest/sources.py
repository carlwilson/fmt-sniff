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
from os import access, path, R_OK, scandir
import re
import tempfile

from botocore import exceptions
from boto3 import client, resource

from corptest.utilities import sha1_path

class SourceDetails(object):
    """Simple class to hold details common to all sources, e.g. name, description."""
    def __init__(self, name, description):
        if not name:
            raise ValueError("Argument name can not be None or an empty string.")
        self.__name = name
        self.__description = description

    @property
    def name(self):
        """Return the source's name, a unique string identifier."""
        return self.__name

    @property
    def description(self):
        """Return a human readable, text description of the source."""
        return self.__description

    def __str__(self): # pragma: no cover
        ret_val = []
        ret_val.append("SourceDetails : [name=")
        ret_val.append(self.name)
        ret_val.append(", description=")
        ret_val.append(str(self.description))
        ret_val.append("]")
        return "".join(ret_val)

class SourceKey(object):
    """Simple class encapsulating 2 parts of a key, the value and whether it's a folder."""
    def __init__(self, value, is_folder=True):
        if not value:
            raise ValueError("Argument value can not be None or an empty string.")
        self.__value = value
        self.__is_folder = is_folder

    @property
    def value(self):
        """ Return the key value, it's unique path. """
        return self.__value

    @property
    def is_folder(self):
        """ Return true if key is that of a file item. """
        return self.__is_folder

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

    def __str__(self): # pragma: no cover
        ret_val = []
        ret_val.append("SourceKey : [value=")
        ret_val.append(self.value)
        ret_val.append(", is_folder=")
        ret_val.append(str(self.is_folder))
        ret_val.append("]")
        return "".join(ret_val)

class SourceBase(object):
    """Abstract base class for Source classes."""
    __metaclass__ = abc.ABCMeta
    def __init__(self, details):
        if not details:
            raise ValueError("Argument details can not be None.")
        self.__details = details

    @property
    def details(self):
        """Return the source details."""
        return self.__details

    @abc.abstractmethod
    def all_file_keys(self): # pragma: no cover
        """Generator that returns all file keys for a source."""
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

class AS3BucketSource(SourceBase):
    """A Source based on an Amazon S3 bucket."""
    FOLDER_REGEX = re.compile('.*/$')
    S3_RESOURCE = None
    def __init__(self, details, bucket_name):
        super().__init__(details)
        if not bucket_name:
            raise ValueError("Argument bucket_name can not be None or an empty string.")
        bucket_exists = self.validate_bucket(bucket_name)
        if not bucket_exists:
            raise ValueError('No AS3 bucket called {} found.'.format(bucket_name))
        self.__bucket_name = bucket_name

    @property
    def bucket_name(self):
        """Return the unique Amazon S3 bucket name."""
        return self.__bucket_name

    def all_file_keys(self):
        bucket = self.S3_RESOURCE.Bucket(self.bucket_name)
        for obj_summary in bucket.objects.all():
            if self.FOLDER_REGEX.match(obj_summary.key) is None:
                yield SourceKey(obj_summary.key, False)

    def list_folders(self, filter_key=None, recurse=False):
        prefix = super().validate_key_and_return_prefix(filter_key)
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        s3_client = client('s3')
        result = s3_client.list_objects_v2(Bucket=self.bucket_name, Prefix=prefix, Delimiter='/')
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
        result = s3_client.list_objects_v2(Bucket=self.bucket_name, Prefix=prefix, Delimiter='/')
        if result.get('Contents'):
            for obj_summary in result.get('Contents'):
                yield SourceKey(obj_summary.get('Key'), False)
        if recurse:
            if result.get('CommonPrefixes'):
                for common_prefix in result.get('CommonPrefixes'):
                    key = SourceKey(common_prefix.get('Prefix'))
                    for res in self.list_files(filter_key=key, recurse=True):
                        yield res

    def get_temp_file(self, key):
        """Creates a temp file copy of a file from the specified image."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        s3_client = client('s3')
        # Open with a named temp file
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            s3_client.download_fileobj(self.bucket_name, key.value, temp)
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

    def __str__(self): # pragma: no cover
        ret_val = []
        ret_val.append("AS3BucketSource : [details=")
        ret_val.append(str(self.details))
        ret_val.append(", bucket_name=")
        ret_val.append(self.bucket_name)
        ret_val.append("]")
        return "".join(ret_val)

class FileSystemSource(SourceBase):
    """A source based on a file system"""
    def __init__(self, details, root):
        super().__init__(details)
        if not root:
            raise ValueError("Argument root can not be None or an empty string.")
        if not path.isdir(root) or not access(root, R_OK):
            raise ValueError("Argument root must be an existing dir")
        self.__root = root

    @property
    def root(self):
        """Return the root path to the file system corpus."""
        return self.__root

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
        for entry in scandir(path.join(self.root, prefix)):
            if list_files and entry.is_file(follow_symlinks=False):
                yield SourceKey(path.join(prefix, entry.name), False)
            if entry.is_dir(follow_symlinks=False):
                if list_folders:
                    yield SourceKey(path.join(prefix, entry.name))
                if recurse:
                    for child in self.yield_keys(prefix=path.join(prefix, entry.name),
                                                 list_files=list_files,
                                                 list_folders=list_folders,
                                                 recurse=True):
                        yield child

    def get_temp_file(self, key):
        """Creates a temp file copy of a file from the specified image."""
        if not key or key.is_folder:
            raise ValueError("Argument key must be a file key.")
        file_path = path.join(self.root, key.value)
        sha1 = sha1_path(file_path)
        return file_path, sha1

    def __str__(self): # pragma: no cover
        ret_val = []
        ret_val.append("FileSystemSource : [details=")
        ret_val.append(str(self.details))
        ret_val.append(", root=")
        ret_val.append(self.root)
        ret_val.append("]")
        return "".join(ret_val)
