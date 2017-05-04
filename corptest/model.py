#!/usr/bin/env python
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
"""SQL Alchemy database model classes."""
import errno
import os
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship, backref

from corptest.database import BASE, DB_SESSION
from corptest.utilities import sha1_path, sha1_string
class SourceDetails(BASE):
    """Simple class to hold details common to all sources, e.g. name, description."""
    __tablename__ = 'source_details'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __name = Column("name", String(256), unique=True)
    __description = Column("description", String(512))

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

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.SourceDetails : [name=")
        ret_val.append(self.name)
        ret_val.append(", description=")
        ret_val.append(str(self.description))
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of SourceDetails instances in the database."""
        return len(SourceDetails.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the SourceDetails instances."""
        return SourceDetails.query.order_by(SourceDetails.__name).all()

    @staticmethod
    def by_name(name):
        """Query for SourceDetails with matching name."""
        if not name:
            raise ValueError("name argument can not be null or empty")
        return SourceDetails.query.filter_by(name=name).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for SourceDetails with matching id."""
        if not id:
            raise ValueError("id argument can not be null")
        return SourceDetails.query.filter_by(id=id).first()

    @staticmethod
    def add(details):
        """Add a SourceDetails instance to the table."""
        _add(details)

class AS3Bucket(BASE):
    """Database table class for an AS3 Bucket details."""
    __tablename__ = "as3_bucket"

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __bucket_name = Column("bucket_name", String(255), unique=True)
    details_id = Column(Integer, ForeignKey('source_details.id'))
    details = relationship('SourceDetails', backref=backref('buckets', lazy='dynamic'))

    def __init__(self, details, bucket_name):
        if not details:
            raise ValueError("Argument details can not be None.")
        if not bucket_name:
            raise ValueError("Argument bucket_name can not be None or an empty string.")
        self.details = details
        self.__bucket_name = bucket_name

    @property
    def bucket_name(self):
        """ Return true if key is that of a file item. """
        return self.__bucket_name

    def __key(self):
        return (self.details, self.bucket_name)

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
        ret_val.append("corptest.model.AS3Bucket : [details=")
        ret_val.append(str(self.details))
        ret_val.append(", bucket_name=")
        ret_val.append(self.__bucket_name)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of AS3Bucket instances in the database."""
        return len(AS3Bucket.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the AS3Bucket instances."""
        return AS3Bucket.query.order_by(AS3Bucket.__bucket_name).all()

    @staticmethod
    def by_bucket_name(bucket_name):
        """Query for AS3Bucket with matching bucket_name."""
        if not bucket_name:
            raise ValueError("bucket_name argument can not be null or empty")
        return AS3Bucket.query.filter_by(__bucket_name=bucket_name).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for AS3Bucket with matching id."""
        if not id:
            raise ValueError("id argument can not be null")
        return AS3Bucket.query.filter_by(id=id).first()

    @staticmethod
    def add(bucket):
        """Add a AS3Bucket instance to the table."""
        _add(bucket)

class FileSystem(BASE):
    """Database table class for a File System details."""
    __tablename__ = "file_system"

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __root = Column("root", String(512), unique=True)
    details_id = Column(Integer, ForeignKey('source_details.id'))
    details = relationship('SourceDetails', backref=backref('file_systems', lazy='dynamic'))

    def __init__(self, details, root):
        if not details:
            raise ValueError("Argument details can not be None.")
        if not root:
            raise ValueError("Argument root can not be None or an empty string.")
        self.details = details
        self.__root = root

    @property
    def root(self):
        """ Return true if key is that of a file item. """
        return self.__root

    def __key(self):
        return (self.details, self.root)

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
        ret_val.append("corptest.model.FileSystem : [details=")
        ret_val.append(str(self.details))
        ret_val.append(", root=")
        ret_val.append(self.__root)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of FileSystem instances in the database."""
        return len(FileSystem.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the FileSystem instances."""
        return FileSystem.query.order_by(FileSystem.__root).all()

    @staticmethod
    def by_root(root):
        """Query for FileSystem with matching root."""
        if not root:
            raise ValueError("root argument can not be null or empty")
        return FileSystem.query.filter_by(__root=root).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for FileSystem with matching id."""
        if not id:
            raise ValueError("id argument can not be null")
        return FileSystem.query.filter_by(id=id).first()

    @staticmethod
    def add(file_system):
        """Add a FileSystem instance to the table."""
        _add(file_system)

class SourceKey(BASE):
    """Simple class encapsulating 2 parts of a key, the value and whether it's a folder."""
    __tablename__ = 'source_key'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __value = Column("value", String(1024))
    __is_folder = Column("is_folder", Boolean)

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

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.SourceKey : [value=")
        ret_val.append(self.value)
        ret_val.append(", is_folder=")
        ret_val.append(str(self.is_folder))
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of SourceKey instances in the database."""
        return len(SourceKey.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the SourceKey instances."""
        return SourceKey.query.order_by(SourceKey.__value).all()

    @staticmethod
    def folders():
        """Convenience method, returns all of the SourceKey folders."""
        return SourceKey.query.filter_by(__is_folder=True).order_by(SourceKey.__value).all()

    @staticmethod
    def files():
        """Convenience method, returns all of the SourceKey instances."""
        return SourceKey.query.filter_by(__is_folder=False).order_by(SourceKey.__value).all()

    @staticmethod
    def by_value(value):
        """Query for SourceKey with matching value."""
        if not value:
            raise ValueError("value argument can not be null or empty")
        return SourceKey.query.filter_by(__value=value).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for SourceKey with matching id."""
        if not id:
            raise ValueError("id argument can not be null")
        return SourceKey.query.filter_by(id=id).first()

    @staticmethod
    def add(key):
        """Add a SourceKey instance to the table."""
        _add(key)

class ByteSequence(BASE):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    __tablename__ = 'byte_sequence'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __sha1 = Column("sha1", String(40), unique=True)
    __size = Column("size", Integer)

    EMPTY_SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

    def __init__(self, sha1=EMPTY_SHA1, size=0):
        self.__sha1 = sha1
        self.__size = size

    @property
    def sha1(self):
        """Returns the SHA-1 hash of the ByteSequence, use as an id."""
        return self.__sha1

    @property
    def size(self):
        """Return the size of the ByteSequence in bytes."""
        return self.__size

    def __key(self):
        return (self.sha1, self.size)

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

    def __rep__(self):
        ret_val = []
        ret_val.append("ByteSequence : [sha1=")
        ret_val.append(self.sha1)
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def default_instance(cls):
        """ Returns the default instance, an empty byte sequence. """
        return ByteSequence()

    @classmethod
    def from_file(cls, source_path):
        """ Creates a new ByteSequence instance from the supplied file path. """
        if not os.path.isfile(source_path):
            raise IOError(errno.ENOENT, os.strerror(errno.ENOENT), source_path)
        sha1 = sha1_path(source_path)
        size = os.path.getsize(source_path)
        return cls(sha1, size)

    @classmethod
    def from_string(cls, source):
        """ Creates a new ByteSequence instance from the supplied string. """
        sha1 = sha1_string(source)
        return cls(sha1, len(source))

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for ByteSequence. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            byte_seq = obj[cls_name]
            return cls(byte_seq['_ByteSequence__sha1'], byte_seq['_ByteSequence__size'])
        return obj

    @staticmethod
    def count():
        """Returns the number of ByteSequence instances in the database."""
        return len(ByteSequence.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the ByteSequence instances."""
        return ByteSequence.query.order_by(ByteSequence.__sha1).all()

    @staticmethod
    def by_sha1(sha1):
        """Query for ByteSequence with matching value."""
        if not sha1:
            raise ValueError("sha1 argument can not be null or empty")
        return ByteSequence.query.filter_by(__sha1=sha1).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequence with matching id."""
        if not id:
            raise ValueError("id argument can not be null")
        return ByteSequence.query.filter_by(id=id).first()

    @staticmethod
    def add(byte_sequence):
        """Add a ByteSequence instance to the table."""
        _add(byte_sequence)

def _add(obj):
    """Add an object instance to the database."""
    if not obj:
        raise ValueError("obj argument can not be null")
    DB_SESSION.add(obj)
    DB_SESSION.commit()
