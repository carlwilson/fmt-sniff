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
from datetime import datetime
import errno
import os
from sqlalchemy import Column, DateTime, Integer, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import backref, relationship

from corptest.database import BASE, DB_SESSION
from corptest.utilities import check_param_not_none, sha1_path, sha1_string, timestamp_fmt
class Source(BASE):
    """Simple class to hold details common to all sources, e.g. name, description."""
    __tablename__ = 'source'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __name = Column("name", String(256), unique=True)
    __description = Column("description", String(512))
    __discriminator = Column('type', String(64))
    __mapper_args__ = {'polymorphic_on': __discriminator}

    def __init__(self, name, description):
        check_param_not_none(name, "name")
        if description is None:
            check_param_not_none(description, "description")
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

    def __key(self):
        return (self.name, self.description)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.Source : [name=")
        ret_val.append(self.name)
        ret_val.append(", description=")
        ret_val.append(str(self.description))
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of Source instances in the database."""
        return len(Source.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the Source instances."""
        return Source.query.order_by(Source.__name).all()

    @staticmethod
    def by_name(name):
        """Query for Source with matching name."""
        check_param_not_none(name, "name")
        return Source.query.filter_by(name=name).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for Source with matching id."""
        check_param_not_none(id, "id")
        return Source.query.filter_by(id=id).first()

    @staticmethod
    def add(source):
        """Add a Source instance to the table."""
        check_param_not_none(source, "source")
        _add(source)

class AS3BucketSource(Source):
    """Database table class for an AS3 Bucket Source details."""
    __mapper_args__ = {'polymorphic_identity': 'as3_bucket_source'}
    __bucket_name = Column("bucket_name", String(255), unique=True)

    def __init__(self, name, description, bucket_name):
        super(AS3BucketSource, self).__init__(name, description)
        check_param_not_none(bucket_name, "bucket_name")
        self.__bucket_name = bucket_name

    @property
    def bucket_name(self):
        """ Return name of the AS3BucketSource. """
        return self.__bucket_name

    def put(self):
        """Add this AS3BucketSource instance to the database."""
        return _add(self)

    def __key(self):
        return (super(AS3BucketSource, self).__key(), self.bucket_name)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.AS3BucketSource : [name=")
        ret_val.append(self.name)
        ret_val.append(", description=")
        ret_val.append(self.description)
        ret_val.append(", bucket_name=")
        ret_val.append(self.bucket_name)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of AS3BucketSource instances in the database."""
        return len(AS3BucketSource.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the AS3BucketSource instances."""
        return AS3BucketSource.query.order_by(AS3BucketSource.__bucket_name).all()

    @staticmethod
    def by_bucket_name(bucket_name):
        """Query for AS3BucketSource with matching bucket_name."""
        check_param_not_none(bucket_name, "bucket_name")
        return AS3BucketSource.query.filter_by(__bucket_name=bucket_name).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for AS3BucketSource with matching id."""
        check_param_not_none(id, "id")
        return AS3BucketSource.query.filter_by(id=id).first()

class FileSystemSource(Source):
    """Database table class for a File System details."""
    __mapper_args__ = {'polymorphic_identity': 'file_system_source'}

    __root = Column("root", String(512), unique=True)

    def __init__(self, name, description, root):
        super(FileSystemSource, self).__init__(name, description)
        check_param_not_none(root, "root")
        self.__root = root

    @property
    def root(self):
        """Return the root folder location of the FileSystemSource."""
        return self.__root

    def put(self):
        """Add this FileSystemSource instance to the database."""
        return _add(self)

    def __key(self):
        return (super(FileSystemSource, self).__key(), self.root)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.FileSystemSource : [name=")
        ret_val.append(str(self.name))
        ret_val.append(", description=")
        ret_val.append(self.description)
        ret_val.append(", root=")
        ret_val.append(self.root)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of FileSystemSource instances in the database."""
        return len(FileSystemSource.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the FileSystemSource instances."""
        return FileSystemSource.query.order_by(FileSystemSource.__root).all()

    @staticmethod
    def by_root(root):
        """Query for FileSystemSource with matching root."""
        check_param_not_none(root, "root")
        return FileSystemSource.query.filter_by(__root=root).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for FileSystemSource with matching id."""
        check_param_not_none(id, "id")
        return FileSystemSource.query.filter_by(id=id).first()

class SourceIndex(BASE):
    """Association table that holds an indexed snapshot of a source's content."""
    __tablename__ = "source_index"

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    source_id = Column(Integer, ForeignKey('source.id'))# pylint: disable-msg=C0103
    __timestamp = Column("timestamp", DateTime)
    __source = relationship("Source")
    __nodes = relationship("Node")
    UniqueConstraint('source_id', 'timestamp', name='uix_source_date')

    def __init__(self, source, timestamp):
        check_param_not_none(source, "source")
        check_param_not_none(timestamp, "timestamp")
        self.__source = source
        self.__timestamp = timestamp

    @property
    def source(self):
        """ Return the Index's source instance. """
        return self.__source

    @property
    def timestamp(self):
        """ Return the SourceIndex's timestamp, the time that the indexing was started. """
        return self.__timestamp

    @property
    def iso_timestamp(self):
        """ Return the ISO formatted String of the SourceIndex's timestamp. """
        return timestamp_fmt(self.__timestamp)

    @property
    def nodes(self):
        """Return all the nodes in the index."""
        return self.__nodes

    def put(self):
        """ Add the SourceIndex to the database."""
        _add(self)

    def __key(self):
        return (self.source, self.timestamp)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.SourceIndex [source=")
        ret_val.append(str(self.source))
        ret_val.append(", timestamp=")
        ret_val.append(self.iso_timestamp)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of SourceIndex instances in the database."""
        return len(SourceIndex.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the SourceIndex instances."""
        return SourceIndex.query.order_by(SourceIndex.id).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for Folder with matching id."""
        check_param_not_none(id, "id")
        if not id:
            raise ValueError("id argument can not be null")
        return SourceIndex.query.filter_by(id=id).first()

    @staticmethod
    def add(source_index):
        """Add a SourceIndex instance to the table."""
        _add(source_index)

class Node(BASE):
    """Encapsulates a node on a file system, base class for folder and data nodes."""
    __tablename__ = 'node'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    source_index_id = Column(Integer, ForeignKey('source_index.id'))# pylint: disable-msg=C0103
    __path = Column("path", String(2048))
    parent_id = Column(Integer, ForeignKey('node.id'))
    __source_index = relationship("SourceIndex")
    __parent = relationship("Folder")
    UniqueConstraint('source_id', 'path', name='uix_source_path')

    def __init__(self, source_index, path):
        check_param_not_none(source_index, "source_index")
        check_param_not_none(path, "path")
        self.__source_index = source_index
        self.__path = path

    @property
    def source(self):
        """ Return the Node's unique path. """
        return self.__source

    @property
    def parent(self):
        """ Return the Node's parent. """
        return self.__parent

    @property
    def path(self):
        """ Return the Node's unique path. """
        return self.__path

    def __key(self):
        return (self.source_id, self.path)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.Node : path=")
        ret_val.append(self.path)
        ret_val.append("]")
        return "".join(ret_val)

class Folder(Node):
    """Class for folder nodes."""
    __children = relationship("Folder", backref=backref('parent', remote_side=[Node.id]))
    def __init__(self, source, path):# pylint: disable-msg=W0235
        super(Folder, self).__init__(source, path)

    @property
    def children(self):
        """Return the child nodes of the folder."""
        return self.__children

    def put(self):
        """ Add the Folder to the database."""
        _add(self)

    @staticmethod
    def count():
        """Returns the number of Node instances in the database."""
        return len(Folder.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the Folder instances."""
        return Folder.query.order_by(Folder.__path).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for Folder with matching id."""
        check_param_not_none(id, "id")
        return Folder.query.filter_by(id=id).first()

    @staticmethod
    def add(folder):
        """Add a Folder instance to the table."""
        check_param_not_none(folder, "folder")
        _add(folder)

class DataNode(Node):
    """Class that encapsulates a data node."""
    __size = Column("size", Integer)
    __last_modified = Column("last_modified", DateTime)

    def __init__(self, source, path, size, last_modified=datetime.now()):
        super(DataNode, self).__init__(source, path)
        check_param_not_none(size, "size")
        if size < 0:
            raise ValueError("Argument size can not be less than zero.")
        check_param_not_none(last_modified, "last_modified")
        self.__size = size
        self.__last_modified = last_modified

    @property
    def size(self):
        """Returns the size of the file in bytes."""
        return self.__size

    @property
    def last_modified(self):
        """Returns the datetime that the file was last modified."""
        return self.__last_modified

    def put(self):
        """Add this DataNode instance to the database."""
        return _add(self)

    def __key(self):
        return (super.key(), self.self.size, self.last_modified)

    def __eq__(self, other):
        """ Define an equality test for FileItem """
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        """ Define an inequality test for FileItem """
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __rep__(self):
        ret_val = []
        ret_val.append("FileItem : [node=")
        ret_val.append(str(super()))
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append(", last_modified=")
        ret_val.append(str(self.last_modified))
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of DataNode instances in the database."""
        return len(DataNode.query.all())

    @staticmethod
    def all():
        """Convenience method, returns all of the DataNode instances."""
        return DataNode.query.all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for DataNode with matching id."""
        check_param_not_none(id, "id")
        return DataNode.query.filter_by(id=id).first()

    @staticmethod
    def add(data_node):
        """Add a DataNode instance to the table."""
        check_param_not_none(data_node, "data_node")
        _add(data_node)

class ByteSequence(BASE):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    __tablename__ = 'byte_sequence'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __sha1 = Column("sha1", String(40), unique=True)
    __size = Column("size", Integer)

    EMPTY_SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

    def __init__(self, sha1=EMPTY_SHA1, size=0):
        check_param_not_none(sha1, "sha1")
        if size < 0:
            raise ValueError("Argument size can not be less than zero.")
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

    def put(self):
        """Add this ByteSequence instance to the database."""
        return _add(self)

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
        check_param_not_none(source_path, "source_path")
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
        check_param_not_none(sha1, "sha1")
        return ByteSequence.query.filter_by(__sha1=sha1).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequence with matching id."""
        check_param_not_none(id, "id")
        return ByteSequence.query.filter_by(id=id).first()

    @staticmethod
    def add(byte_sequence):
        """Add a ByteSequence instance to the table."""
        check_param_not_none(byte_sequence, "byte_sequence")
        _add(byte_sequence)

def _add(obj):
    """Add an object instance to the database."""
    check_param_not_none(obj, "obj")
    DB_SESSION.add(obj)
    DB_SESSION.commit()
