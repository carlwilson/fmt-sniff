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
from sqlalchemy import UniqueConstraint, Boolean, func
from sqlalchemy.orm import relationship

from .database import BASE, DB_SESSION
from .utilities import check_param_not_none, sha1_path, sha1_string, timestamp_fmt
SCHEMES = {
    'AS3': "as3",
    'FILE': "file"
}
class Source(BASE):
    """Simple class to hold details common to all sources, e.g. name, description."""
    __tablename__ = 'source'

    id = Column(Integer, primary_key=True) # pylint: disable-msg=C0103
    name = Column(String(256), unique=True, nullable=False)
    description = Column("description", String(512))
    scheme = Column(String(10), nullable=False)
    location = Column(String(1024), nullable=False)

    def __init__(self, name, description, scheme, location):
        check_param_not_none(name, "name")
        check_param_not_none(description, "description")
        check_param_not_none(scheme, "scheme")
        check_param_not_none(location, "location")
        self.name = name
        self.description = description
        self.scheme = scheme
        self.location = location

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
        return Source.query.order_by(Source.name).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for Source with matching id."""
        check_param_not_none(id, "id")
        return Source.query.filter(Source.id == id).first()

    @staticmethod
    def by_name(name):
        """Query for Source with matching name."""
        check_param_not_none(name, "name")
        return Source.query.filter(Source.name == name).first()

    @staticmethod
    def by_scheme(scheme):
        """Query for alls Sources with matching scheme."""
        check_param_not_none(scheme, "scheme")
        return Source.query.filter(Source.scheme == scheme).all()

    @staticmethod
    def by_location(location):
        """Query for Source with matching location."""
        check_param_not_none(location, "location")
        return Source.query.filter(Source.location == location).all()

    @staticmethod
    def add(source):
        """Add a Source instance to the table."""
        check_param_not_none(source, "source")
        _add(source)

class SourceIndex(BASE):
    """Association table that holds an indexed snapshot of a source's content."""
    __tablename__ = "source_index"

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    source_id = Column(Integer, ForeignKey('source.id'), nullable=False)# pylint: disable-msg=C0103
    root_key = Column(String(2048), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source = relationship("Source")
    keys = relationship("Key")
    __table_args__ = (UniqueConstraint('source_id', 'timestamp', name='uix_source_date'),)

    def __init__(self, source, timestamp=None, root_key=None):
        check_param_not_none(source, "source")
        self.source = source
        self.timestamp = timestamp if timestamp else datetime.now()
        self.root_key = '' if not root_key else root_key

    @property
    def iso_timestamp(self):
        """ Return the ISO formatted String of the SourceIndex's timestamp. """
        return timestamp_fmt(self.timestamp, True)

    @property
    def short_iso_timestamp(self):
        """ Return the ISO formatted String of the SourceIndex's timestamp. """
        return timestamp_fmt(self.timestamp)

    @property
    def key_count(self):
        """Return all the keys in the index."""
        return Key.query.filter(Key.source_index_id == self.id).count()

    @property
    def size(self):
        """Returns the total size in bytes of all files in the index."""
        return DB_SESSION.query(func.sum(Key.size)).group_by(Key.source_index_id).\
            filter(Key.source_index_id == self.id).scalar()

    @property
    def to_download(self):
        """Returns true if there is still data to download for this index."""
        if self.source.scheme == SCHEMES['FILE']:
            return False
        return Key.query.filter(Key.source_index_id == self.id,
                                Key.byte_sequence_id == None).count() > 0

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
    source_index_id = Column(Integer, ForeignKey('source_index.id'), nullable=False)
    byte_sequence_id = Column(Integer, ForeignKey('byte_sequence.id'))
    path = Column(String(2048), nullable=False)
    size = Column(Integer, nullable=False)
    last_modified = Column(DateTime, nullable=False)

    source_index = relationship("SourceIndex")
    byte_sequence = relationship("ByteSequence")
    __table_args__ = (UniqueConstraint('source_index_id', 'path', name='uix_source_path'),)

    def __init__(self, source_index, path, size=0, last_modified=None, byte_sequence=None):
        check_param_not_none(source_index, "source_index")
        check_param_not_none(path, "path")
        if size is None:
            raise ValueError("Argument size can not be None.")
        if size < 0:
            raise ValueError("Argument size can not be less than zero.")
        if not last_modified:
            last_modified = datetime.now()
        self.source_index = source_index
        self.path = path
        self.size = size
        self.last_modified = last_modified
        self.byte_sequence = byte_sequence

    @property
    def name(self):
        """Return the name of the item without the path."""
        parts = self.path.split('/')
        return parts[-2] if self.path.endswith('/') else parts[-1]

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
        ret_val.append(", index={}".format(self.source_index_id))
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
    def by_index_id(id):# pylint: disable-msg=W0622,C0103
        """Query for DataNode with matching id."""
        check_param_not_none(id, "id")
        return Key.query.filter(Key.source_index_id == id).all()

    @staticmethod
    def add(data_node):
        """Add a DataNode instance to the table."""
        check_param_not_none(data_node, "data_node")
        _add(data_node)

class ByteSequence(BASE):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    __tablename__ = 'byte_sequence'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    sha1 = Column(String(40), unique=True, nullable=False)
    size = Column(Integer, nullable=False)

    EMPTY_SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

    def __init__(self, sha1=EMPTY_SHA1, size=0):
        check_param_not_none(sha1, "sha1")
        if size < 0:
            raise ValueError("Argument size can not be less than zero.")
        if size < 1 and sha1 != self.EMPTY_SHA1:
            raise ValueError('If size is zero SHA1 must be {}'.format(self.EMPTY_SHA1))
        self.sha1 = sha1
        self.size = size

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

    def __str__(self):
        return self.__rep__()

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
            return cls(byte_seq['sha1'], byte_seq['size'])
        return obj

    @staticmethod
    def count():
        """Returns the number of ByteSequence instances in the database."""
        return ByteSequence.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the ByteSequence instances."""
        return ByteSequence.query.order_by(ByteSequence.sha1).all()

    @staticmethod
    def by_sha1(sha1):
        """Query for ByteSequence with matching value."""
        check_param_not_none(sha1, "sha1")
        return ByteSequence.query.filter(ByteSequence.sha1 == sha1).first()

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
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(100))
    reference = Column(String(512), unique=True)
    versions = relationship("FormatToolRelease", back_populates='format_tool')

    def __init__(self, name, description, reference):
        check_param_not_none(name, "name")
        check_param_not_none(description, "description")
        check_param_not_none(reference, "reference")
        self.name = name
        self.description = description
        self.reference = reference

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
        ret_val.append(self.description)
        ret_val.append(", reference =")
        ret_val.append(self.reference)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of FormatTool instances in the database."""
        return FormatTool.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the FormatTool instances."""
        return FormatTool.query.order_by(FormatTool.name).all()

    @staticmethod
    def by_name(name):
        """Query for FormatTool with matching name."""
        check_param_not_none(name, "name")
        return FormatTool.query.filter(FormatTool.name == name).first()

    @staticmethod
    def by_reference(reference):
        """Query for FormatTool with matching URL refernce."""
        check_param_not_none(reference, "nareferenceme")
        return FormatTool.query.filter(FormatTool.reference == reference).first()

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

    @classmethod
    def putdate(cls, name, description, reference):
        """Add a FormatTool instance to the table."""
        check_param_not_none(name, "name")
        check_param_not_none(description, "description")
        check_param_not_none(reference, "reference")
        ret_val = FormatTool.by_name(name)
        if ret_val is None:
            ret_val = cls(name, description, reference)
            cls.add(ret_val)
        return ret_val

class FormatToolRelease(BASE):
    """An individual release of a particular format tool."""
    __tablename__ = 'format_tool_release'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    format_tool_id = Column(Integer,
                            ForeignKey('format_tool.id'), nullable=False)
    format_tool = relationship("FormatTool", back_populates='versions')
    version = Column(String(50), nullable=False)
    available = Column(Boolean, nullable=False)
    enabled = Column(Boolean, nullable=False)
    __table_args__ = (UniqueConstraint('format_tool_id', 'version', name='uix_tool_version'),)

    def __init__(self, format_tool, version, available=True, enabled=True):
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(available, "available")
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(enabled, "enabled")
        self.format_tool = format_tool
        self.version = version
        self.available = available
        self.enabled = enabled

    def set_enabled(self, value):
        """Returns true if the format tool is currently enabled"""
        self.enabled = value
        DB_SESSION.commit()

    def disable(self):
        """Sets the tool's enabled flag False."""
        self.set_enabled(False)

    def enable(self):
        """Sets the tool's enabled flag True."""
        self.set_enabled(True)

    def put(self):
        """Add this FormatToolRelease instance to the database."""
        return _add(self)

    def __key(self):
        return (self.format_tool_id, self.version)

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
        return FormatToolRelease.query.filter(FormatToolRelease.version == version).first()

    @staticmethod
    def by_tool_and_version(format_tool, version):
        """Query for FormatToolRelease with matching version."""
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(version, "version")
        return FormatToolRelease.query.filter(and_(FormatToolRelease.format_tool_id == \
                                                   format_tool.id,
                                                   FormatToolRelease.version == version)).first()

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

    @classmethod
    def putdate(cls, format_tool, version, available=True, enabled=True):
        """Add a FormatToolRelease instance to the table."""
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(available, "available")
        check_param_not_none(format_tool, "format_tool")
        check_param_not_none(enabled, "enabled")
        ret_val = FormatToolRelease.by_tool_and_version(format_tool, version)
        if ret_val is None:
            ret_val = cls(format_tool, version, available, enabled)
            _add(ret_val)
        return ret_val

    @staticmethod
    def get_available():
        """Retrieve all available format tools."""
        return FormatToolRelease.query.filter(
            FormatToolRelease.available == True).all()# pylint: disable-msg=C0121

    @staticmethod
    def all_available():
        """Sets every FormatToolRelease's available flag to false."""
        FormatToolRelease.set_availability(True)

    @staticmethod
    def all_unavailable():
        """Sets every FormatToolRelease's available flag to false."""
        FormatToolRelease.set_availability(False)

    @staticmethod
    def set_availability(availability):
        """Sets every FormatToolRelease's available flag to value of availability."""
        stmt = FormatToolRelease.__table__.update().\
            values({
                'available': availability,
                })
        DB_SESSION.execute(stmt, [])# pylint: disable-msg=E1101
        DB_SESSION.commit()

    @staticmethod
    def get_enabled():
        """Retrieve all enabled format tools."""
        return FormatToolRelease.query.filter(
            FormatToolRelease.enabled == True).all()# pylint: disable-msg=C0121

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
