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
import os.path
from sqlalchemy import and_, Column, DateTime, Integer, String, ForeignKey
from sqlalchemy import UniqueConstraint, Boolean
from sqlalchemy.orm import relationship

from .database import BASE, DB_SESSION, ENGINE
from .utilities import check_param_not_none, sha1_path, sha1_string, timestamp_fmt
SCHEMES = {
    'AS3': "as3",
    'FILE': "file"
}
class Source(BASE):
    """Simple class to hold details common to all sources, e.g. name, description."""
    __tablename__ = 'source'

    id = Column(Integer, primary_key=True) # pylint: disable-msg=C0103
    __name = Column("name", String(256), unique=True)
    __description = Column("description", String(512))
    __scheme = Column("scheme", String(10))
    __location = Column("location", String(1024))

    def __init__(self, name, description, scheme, location):
        check_param_not_none(name, "name")
        check_param_not_none(description, "description")
        check_param_not_none(scheme, "scheme")
        check_param_not_none(location, "location")
        self.__name = name
        self.__description = description
        self.__scheme = scheme
        self.__location = location

    @property
    def name(self):
        """Return the source's name, a unique string identifier."""
        return self.__name

    @property
    def description(self):
        """Return a human readable, text description of the source."""
        return self.__description

    @property
    def scheme(self):
        """Return the scheme used for resolving the location."""
        return self.__scheme

    @property
    def location(self):
        """Return a resolvable location where the data can be found."""
        return self.__location

    def __key(self):
        return (self.name, self.description, self.location)

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
        ret_val.append(", scheme=")
        ret_val.append(str(self.scheme))
        ret_val.append(", location=")
        ret_val.append(str(self.location))
        ret_val.append("]")
        return "".join(ret_val)

    def __str__(self):
        return self.__rep__()

    @staticmethod
    def count():
        """Returns the number of Source instances in the database."""
        return Source.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the Source instances."""
        return Source.query.order_by(Source.__name).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for Source with matching id."""
        check_param_not_none(id, "id")
        return Source.query.filter(Source.id == id).first()

    @staticmethod
    def by_name(name):
        """Query for Source with matching name."""
        check_param_not_none(name, "name")
        return Source.query.filter(Source.__name == name).first()

    @staticmethod
    def by_scheme(scheme):
        """Query for alls Sources with matching scheme."""
        check_param_not_none(scheme, "scheme")
        return Source.query.filter(Source.__scheme == scheme).all()

    @staticmethod
    def by_location(location):
        """Query for Source with matching location."""
        check_param_not_none(location, "location")
        return Source.query.filter(Source.__location == location).all()

    @staticmethod
    def add(source):
        """Add a Source instance to the table."""
        check_param_not_none(source, "source")
        _add(source)

class SourceIndex(BASE):
    """Association table that holds an indexed snapshot of a source's content."""
    __tablename__ = "source_index"

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __source_id = Column("source_id", Integer, ForeignKey('source.id'))# pylint: disable-msg=C0103
    __timestamp = Column("timestamp", DateTime)
    __root_key = Column("root_path", String(2048))
    __source = relationship("Source")
    __keys = relationship("Key")
    __table_args__ = (UniqueConstraint('source_id', 'timestamp', name='uix_source_date'),)

    def __init__(self, source, timestamp=None):
        check_param_not_none(source, "source")
        if not timestamp:
            timestamp = datetime.now()
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
    def keys(self):
        """Return all the keys in the index."""
        return self.__keys

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
        return SourceIndex.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the SourceIndex instances."""
        return SourceIndex.query.order_by(SourceIndex.id).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for SourceIndex with matching id."""
        check_param_not_none(id, "id")
        if not id:
            raise ValueError("id argument can not be null")
        return SourceIndex.query.filter(SourceIndex.id == id).first()

    @staticmethod
    def add(source_index):
        """Add a SourceIndex instance to the table."""
        _add(source_index)

class Key(BASE):
    """Encapsulates a key on a file system for storing data."""
    __tablename__ = 'key'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __source_index_id = Column("source_index_id",
                               Integer, ForeignKey('source_index.id'))# pylint: disable-msg=C0103
    __path = Column("path", String(2048))
    __size = Column("size", Integer)
    __last_modified = Column("last_modified", DateTime)

    __source_index = relationship("SourceIndex")
    __table_args__ = (UniqueConstraint('source_index_id', 'path', name='uix_source_path'),)

    def __init__(self, source_index, path, size, last_modified=None):
        check_param_not_none(source_index, "source_index")
        check_param_not_none(path, "path")
        if size is None:
            raise ValueError("Argument size can not be None.")
        if size < 0:
            raise ValueError("Argument size can not be less than zero.")
        if not last_modified:
            last_modified = datetime.now()
        self.__source_index = source_index
        self.__path = path
        self.__size = size
        self.__last_modified = last_modified

    @property
    def source_index(self):
        """ Return the Node's unique path. """
        return self.__source_index

    @property
    def path(self):
        """ Return the Node's unique path. """
        return self.__path

    @property
    def size(self):
        """Returns the size of the file in bytes."""
        return self.__size

    @property
    def last_modified(self):
        """Returns the datetime that the file was last modified."""
        return self.__last_modified

    def __key(self):
        return (self.source_index, self.path, self.size, self.last_modified)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __str__(self): # pragma: no cover
        return self.__rep__()

    def __rep__(self): # pragma: no cover
        ret_val = []
        ret_val.append("corptest.model.Key : id={}".format(self.id))
        ret_val.append(", index={}".format(self.__source_index_id))
        ret_val.append(", path=")
        ret_val.append(self.path)
        ret_val.append(", size=")
        ret_val.append(str(self.size))
        ret_val.append(", last_modified=")
        ret_val.append(str(self.last_modified))
        ret_val.append("]")
        return "".join(ret_val)

    def put(self):
        """Add this DataNode instance to the database."""
        return _add(self)

    @staticmethod
    def count():
        """Returns the number of DataNode instances in the database."""
        return Key.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the DataNode instances."""
        return Key.query.all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for DataNode with matching id."""
        check_param_not_none(id, "id")
        return Key.query.filter(Key.id == id).first()

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
        return ByteSequence.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the ByteSequence instances."""
        return ByteSequence.query.order_by(ByteSequence.__sha1).all()

    @staticmethod
    def by_sha1(sha1):
        """Query for ByteSequence with matching value."""
        check_param_not_none(sha1, "sha1")
        return ByteSequence.query.filter(ByteSequence.__sha1 == sha1).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequence with matching id."""
        check_param_not_none(id, "id")
        return ByteSequence.query.filter(ByteSequence.id == id).first()

    @staticmethod
    def add(byte_sequence):
        """Add a ByteSequence instance to the table."""
        check_param_not_none(byte_sequence, "byte_sequence")
        _add(byte_sequence)

    @staticmethod
    def is_sha1(maybe_sha):
        """Method that checks whether a passed string is a valid sha1 hash string, that
        is a 40 character hex string. Thanks to mVChr from this Stack Overflow thread:
        http://stackoverflow.com/questions/32234169/sha1-string-regex-for-python."""
        if len(maybe_sha) != 40:
            return False
        try:
            int(maybe_sha, 16)
        except ValueError:
            return False
        return True

class FormatTool(BASE):
    """Class to hold the details of a format identification tool."""
    __tablename__ = 'format_tool'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __name = Column("name", String(100), unique=True)
    __description = Column("description", String(100))
    __reference = Column("reference", String(512), unique=True)
    versions = relationship("FormatToolRelease", back_populates='format_tool')

    def __init__(self, name, description, reference):
        check_param_not_none(name, "name")
        check_param_not_none(description, "description")
        check_param_not_none(reference, "reference")
        self.__name = name
        self.__description = description
        self.__reference = reference

    @property
    def name(self):
        """Returns the recognised name of the format tool"""
        return self.__name

    @property
    def description(self):
        """Returns the textual description of the format tool"""
        return self.__description

    @property
    def reference(self):
        """Returns a URL that refers to the format tools project page."""
        return self.__reference

    def put(self):
        """Add this FormatTool instance to the database."""
        return _add(self)

    def __key(self):
        return (self.name, self.reference)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __str__(self):
        return self.__rep__()

    def __rep__(self):
        ret_val = []
        ret_val.append("FormatTool : [id =")
        ret_val.append(str(self.id))
        ret_val.append(", name =")
        ret_val.append(self.name)
        ret_val.append(", description =")
        ret_val.append(self.__description)
        ret_val.append(", reference =")
        ret_val.append(self.__reference)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of FormatTool instances in the database."""
        return FormatTool.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the FormatTool instances."""
        return FormatTool.query.order_by(FormatTool.__name).all()

    @staticmethod
    def by_name(name):
        """Query for FormatTool with matching name."""
        check_param_not_none(name, "name")
        return FormatTool.query.filter(FormatTool.__name == name).first()

    @staticmethod
    def by_reference(reference):
        """Query for FormatTool with matching URL refernce."""
        check_param_not_none(reference, "nareferenceme")
        return FormatTool.query.filter(FormatTool.__reference == reference).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for FormatTool with matching id."""
        check_param_not_none(id, "id")
        return FormatTool.query.filter(FormatTool.id == id).first()

    @staticmethod
    def add(format_tool):
        """Add a FormatTool instance to the table."""
        check_param_not_none(format_tool, "format_tool")
        _add(format_tool)

class FormatToolRelease(BASE):
    """An individual release of a particular format tool."""
    __tablename__ = 'format_tool_release'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    __format_tool_id = Column("format_tool_id", Integer,
                              ForeignKey('format_tool.id'))
    format_tool = relationship("FormatTool", back_populates='versions')
    __version = Column("version", String(50))
    __available = Column("available", Boolean)
    __enabled = Column("enabled", Boolean)
    UniqueConstraint('format_tool_id', 'version', name='uix__tool_version')

    def __init__(self, format_tool, version, available=True, enabled=True):
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(version, "version")
        self.format_tool = format_tool
        self.__version = version
        self.__available = available
        self.__enabled = enabled

    @property
    def version(self):
        """Returns the unique version number of the format tool"""
        return self.__version

    @property
    def available(self):
        """Returns true if the format tool is currently available"""
        return self.__available

    @property
    def enabled(self):
        """Returns true if the format tool is currently enabled"""
        return self.__enabled

    def disable(self):
        self.__enabled = False
        DB_SESSION.commit()

    def enable(self):
        self.__enabled = True
        DB_SESSION.commit()

    def put(self):
        """Add this FormatToolRelease instance to the database."""
        return _add(self)

    def __key(self):
        return (self.__format_tool_id, self.version)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __str__(self):
        return self.__rep__()

    def __rep__(self):
        ret_val = []
        ret_val.append("corptest.model.FormatToolRelease : [id = ")
        ret_val.append(str(self.id))
        ret_val.append(", format_tool = ")
        ret_val.append(str(self.format_tool))
        ret_val.append(", version = ")
        ret_val.append(self.version)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of FormatToolRelease instances in the database."""
        return FormatToolRelease.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the FormatToolRelease instances."""
        return FormatToolRelease.query.all()

    @staticmethod
    def by_version(version):
        """Query for FormatToolRelease with matching version."""
        check_param_not_none(version, "version")
        return FormatToolRelease.query.filter(FormatToolRelease.__version == version).first()

    @staticmethod
    def by_tool_and_version(format_tool, version):
        """Query for FormatToolRelease with matching version."""
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(version, "version")
        return FormatToolRelease.query.filter(and_(FormatToolRelease.__format_tool_id == \
                                                   format_tool.id,
                                                   FormatToolRelease.__version == version)).first()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for FormatToolRelease with matching id."""
        check_param_not_none(id, "id")
        return FormatToolRelease.query.filter(FormatToolRelease.id == id).first()

    @staticmethod
    def add(format_tool_release):
        """Add a FormatToolRelease instance to the table."""
        check_param_not_none(format_tool_release, "format_tool_release")
        _add(format_tool_release)

    @staticmethod
    def get_available():
        """Retrieve all available format tools."""
        return FormatToolRelease.query.filter(FormatToolRelease.__available == True).all()

    @staticmethod
    def all_unavailable():
        stmt = FormatToolRelease.__table__.update().\
            values({
                'available': False,
                })
        DB_SESSION.execute(stmt, [])
        DB_SESSION.commit()

    @staticmethod
    def get_enabled():
        """Retrieve all enabled format tools."""
        return FormatToolRelease.query.filter(FormatToolRelease.__enabled == True).all()

def init_db():
    """Initialise the database."""
    BASE.metadata.create_all(bind=ENGINE)

def _add(obj):
    """Add an object instance to the database."""
    check_param_not_none(obj, "obj")
    DB_SESSION.add(obj)
    DB_SESSION.commit()

def _add_all(objects):
    """Add all objects form an iterable to the database."""
    check_param_not_none(objects, "objects")
    for obj in objects:
        check_param_not_none(obj, "obj")
        DB_SESSION.add(obj)
    DB_SESSION.commit()
