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
import logging

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy import UniqueConstraint, func
from sqlalchemy.orm import relationship

from .database import BASE, DB_SESSION, ENGINE
from .model_sources import Key, ByteSequence
from .model_sources import _add
from .utilities import check_param_not_none
class Property(BASE):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    __tablename__ = 'property'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))

    def __init__(self, name, description=None):
        check_param_not_none(name, "name")
        self.name = name
        self.description = description

    def put(self):
        """Add this ByteSequence instance to the database."""
        return _add(self)

    def __key(self):
        return self.name

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
        ret_val.append("Property : [name=")
        ret_val.append(self.name)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of Property instances in the database."""
        return Property.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the Property instances."""
        return Property.query.order_by(Property.name).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for Property with matching id."""
        check_param_not_none(id, "id")
        return Property.query.filter(Property.id == id).first()

    @staticmethod
    def by_name(name):# pylint: disable-msg=W0622,C0103
        """Query for Property with matching id."""
        check_param_not_none(name, "name")
        return Property.query.filter(Property.name == name).first()

    @classmethod
    def putdate(cls, name, description=None):
        """Create or update the Property."""
        ret_val = cls.by_name(name)
        if ret_val is None:
            ret_val = Property(name, description)
        elif description and description != ret_val.description:
            ret_val.description = description
        ret_val.put()
        return ret_val

    @staticmethod
    def add(to_add):
        """Add a property instance to the table."""
        check_param_not_none(property, "property")
        _add(to_add)

class PropertyValue(BASE):
    """Key attributes for all byte sequences, i.e. arbitary blobs of data."""
    __tablename__ = 'property_value'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    value = Column(String(1024), nullable=False, unique=True)

    def __init__(self, value):
        value = value if value else ''
        self.value = str(value).strip()

    def put(self):
        """Add this Property instance to the database."""
        return _add(self)

    def __key(self):
        return self.value

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
        ret_val.append("PropertyValue : [value=")
        ret_val.append(self.value)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of ByteSequence instances in the database."""
        return PropertyValue.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the ByteSequence instances."""
        return PropertyValue.query.order_by(PropertyValue.value).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequence with matching id."""
        check_param_not_none(id, "id")
        return PropertyValue.query.filter(PropertyValue.id == id).first()

    @staticmethod
    def by_value(value):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequence with matching id."""
        value = value if value else ''
        return PropertyValue.query.filter(PropertyValue.value == str(value)).first()

    @staticmethod
    def add(to_add):
        """Add a property instance to the table."""
        check_param_not_none(property, "property")
        _add(to_add)

    @classmethod
    def putdate(cls, value):
        """Create or update the Property."""
        value = str(value).strip()
        logging.debug("Checking value: %s", value)
        ret_val = cls.by_value(value)
        logging.debug("Returned value: %s", ret_val)
        if ret_val is None:
            ret_val = PropertyValue(value)
            cls.add(ret_val)
        return ret_val

class KeyProperty(BASE):
    """Properties assigned to SourceKeys."""
    __tablename__ = 'key_properties'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    key_id = Column(Integer, ForeignKey('key.id'), nullable=False)
    prop_id = Column(Integer, ForeignKey('property.id'), nullable=False)
    prop_val_id = Column(Integer, ForeignKey('property_value.id'), nullable=False)

    key = relationship('Key')
    prop = relationship('Property')
    prop_val = relationship('PropertyValue')
    __table_args__ = (UniqueConstraint('key_id', 'prop_id', name='uix_key_property'),)

    def __init__(self, key, prop, prop_val):
        check_param_not_none(key, "key")
        check_param_not_none(prop, "prop")
        check_param_not_none(prop_val, "prop_val")
        self.key = key
        self.prop = prop
        self.prop_val = prop_val

    @property
    def qualified_name(self):
        """Return the qualified name of the property value with namespace."""
        ret_val = []
        ret_val.append(self.key.source_index.source.namespace)
        ret_val.append(':')
        ret_val.append(self.prop.name)
        return "".join(ret_val)

    @property
    def namespace(self):
        """Return the namespace of the source for this key property."""
        return self.key.source.namespace

    def put(self):
        """Add this KeyProperty instance to the database."""
        return _add(self)

    def __key(self):
        return (self.key, self.prop, self.prop_val)

    def __eq__(self, other):
        """ Define an equality test for KeyProperty """
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        """ Define an inequality test for KeyProperty """
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __str__(self):
        return self.__rep__()

    def __rep__(self):
        ret_val = []
        ret_val.append("KeyProperty : [key=")
        ret_val.append(self.key)
        ret_val.append(", prop=")
        ret_val.append(self.prop)
        ret_val.append(", prop_val=")
        ret_val.append(self.prop_val)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of KeyProperty instances in the database."""
        return KeyProperty.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the KeyProperty instances."""
        return KeyProperty.query.order_by(KeyProperty.prop_id).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for KeyProperty with matching id."""
        check_param_not_none(id, "id")
        return KeyProperty.query.filter(KeyProperty.id == id).first()

    @staticmethod
    def by_prop_id(id):# pylint: disable-msg=W0622,C0103
        """Query for KeyProperty with matching id."""
        check_param_not_none(id, "id")
        return KeyProperty.query.filter(KeyProperty.prop_id == id).all()

    @staticmethod
    def by_key_id(id):# pylint: disable-msg=W0622,C0103
        """Query for KeyProperty with matching id."""
        check_param_not_none(id, "id")
        return KeyProperty.query.filter(KeyProperty.key_id == id).all()

    @staticmethod
    def by_key_and_prop_id(key_id, prop_id):# pylint: disable-msg=W0622,C0103
        """Query for KeyProperty with matching id."""
        check_param_not_none(id, "id")
        return KeyProperty.query.filter(KeyProperty.prop_id == prop_id,
                                        KeyProperty.key_id == key_id).first()

    @staticmethod
    def get_properties_for_index(source_index_id):
        """Returns the total numbers of properties of all files in the index."""
        return DB_SESSION.query(Property.id, Property.name,
                                func.count(Key.id).label('prop_count')).\
                                distinct(Property.id, Property.name).\
                                group_by(Property.id, Property.name).\
                                join(KeyProperty).join(Key).\
                                filter(Key.source_index_id == source_index_id).all()

    @staticmethod
    def get_property_values_for_index(source_index_id, prop_id):
        """Returns the total size in bytes of all files in the index."""
        return DB_SESSION.query(PropertyValue.value, PropertyValue.id,
                                func.sum(ByteSequence.size).label('prop_size'),\
                                func.count(Key.id).label('prop_count')).\
                                distinct(PropertyValue.value).\
                                group_by(PropertyValue.id, PropertyValue.value).\
                                join(KeyProperty).\
                                filter(KeyProperty.prop_id == prop_id).join(Key).\
                                filter(Key.source_index_id == source_index_id).\
                                join(ByteSequence).all()

    @staticmethod
    def get_keys_for_property_value(source_index_id, prop_val_id):
        """Returns all of the Keys with a particular property value from a particular
        source index."""
        return DB_SESSION.query(Key).join(KeyProperty).\
                                filter(KeyProperty.prop_val_id == prop_val_id).\
                                filter(Key.source_index_id == source_index_id).all()

    @classmethod
    def putdate(cls, key, prop, prop_val):
        """Create or update the KeyProperty."""
        ret_val = cls.by_key_and_prop_id(key.id, prop.id)
        if ret_val is None:
            ret_val = KeyProperty(key, prop, prop_val)
            ret_val.put()
        return ret_val

class ByteSequenceProperty(BASE):
    """Properties assigned to ByteSequences."""
    __tablename__ = 'byte_sequence_properties'

    id = Column(Integer, primary_key=True)# pylint: disable-msg=C0103
    byte_sequence_id = Column(Integer, ForeignKey('byte_sequence.id'), nullable=False)
    format_tool_release_id = Column(Integer, ForeignKey('format_tool_release.id'), nullable=False)
    prop_id = Column(Integer, ForeignKey('property.id'), nullable=False)
    prop_val_id = Column(Integer, ForeignKey('property_value.id'), nullable=False)

    byte_sequence = relationship('ByteSequence')
    format_tool_release = relationship('FormatToolRelease')
    prop = relationship('Property')
    prop_val = relationship('PropertyValue')

    __table_args__ = (UniqueConstraint('byte_sequence_id', 'format_tool_release_id',
                                       'prop_id', name='uix_bs_property'),)

    def __init__(self, byte_sequence, format_tool_release, prop, prop_val):
        check_param_not_none(byte_sequence, "byte_sequence")
        check_param_not_none(format_tool_release, "format_tool_release")
        check_param_not_none(prop, "prop")
        check_param_not_none(prop_val, "prop_val")
        self.byte_sequence = byte_sequence
        self.format_tool_release = format_tool_release
        self.prop = prop
        self.prop_val = prop_val

    @property
    def qualified_name(self):
        """Return the qualified name of the property value with namespace."""
        ret_val = []
        ret_val.append(self.format_tool_release.format_tool.namespace)
        ret_val.append(':')
        ret_val.append(self.prop.name)
        return "".join(ret_val)

    @property
    def namespace(self):
        """Return the namspace of the too for this byte sequence property."""
        return self.format_tool_release.format_tool.namespace

    def put(self):
        """Add this ByteSequenceProperty instance to the database."""
        return _add(self)

    def __key(self):
        return (self.byte_sequence, self.prop, self.prop_val)

    def __eq__(self, other):
        """ Define an equality test for ByteSequenceProperty """
        if isinstance(other, self.__class__):
            return self.__key() == other.__key()
        return False

    def __ne__(self, other):
        """ Define an inequality test for ByteSequenceProperty """
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__key())

    def __str__(self):
        return self.__rep__()

    def __rep__(self):
        ret_val = []
        ret_val.append("ByteSequenceProperty : [byte_sequence=")
        ret_val.append(self.byte_sequence)
        ret_val.append(", prop=")
        ret_val.append(self.prop)
        ret_val.append(", prop_val=")
        ret_val.append(self.prop_val)
        ret_val.append("]")
        return "".join(ret_val)

    @staticmethod
    def count():
        """Returns the number of ByteSequenceProperty instances in the database."""
        return ByteSequenceProperty.query.count()

    @staticmethod
    def all():
        """Convenience method, returns all of the ByteSequenceProperty instances."""
        return ByteSequenceProperty.query.order_by(ByteSequenceProperty.prop_id).all()

    @staticmethod
    def by_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequenceProperty with matching id."""
        check_param_not_none(id, "id")
        return ByteSequenceProperty.query.filter(ByteSequenceProperty.id == id).first()

    @staticmethod
    def by_prop_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequenceProperty with matching id."""
        check_param_not_none(id, "id")
        return ByteSequenceProperty.query.filter(ByteSequenceProperty.prop_id == id).all()

    @staticmethod
    def by_byte_sequence_id(id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequenceProperty with matching id."""
        check_param_not_none(id, "id")
        return ByteSequenceProperty.query.filter(ByteSequenceProperty.byte_sequence_id == id).all()

    @staticmethod
    def by_key_and_byte_sequence_id(byte_sequence_id, prop_id):# pylint: disable-msg=W0622,C0103
        """Query for ByteSequenceProperty with matching id."""
        check_param_not_none(id, "id")
        return ByteSequenceProperty.query.filter(ByteSequenceProperty.prop_id == prop_id,
                                                 ByteSequenceProperty.byte_sequence_id \
                                                 == byte_sequence_id).first()

    @staticmethod
    def get_properties_for_index(source_index_id):
        """Returns the total numbers of properties of all files in the index."""
        return DB_SESSION.query(Property.id, Property.name,
                                func.count(Key.id).label('prop_count')).\
                                distinct(Property.id, Property.name).\
                                group_by(Property.id, Property.name).\
                                join(ByteSequenceProperty).join(ByteSequence).\
                                join(Key).\
                                filter(Key.source_index_id == source_index_id).all()

    @staticmethod
    def get_property_values_for_index(source_index_id, prop_id):
        """Returns the total size in bytes of all files in the index."""
        return DB_SESSION.query(PropertyValue.value, PropertyValue.id,
                                func.sum(ByteSequence.size).label('prop_size'),\
                                func.count(Key.id).label('prop_count')).\
                                distinct(PropertyValue.value).\
                                group_by(PropertyValue.id, PropertyValue.value).\
                                join(ByteSequenceProperty).\
                                filter(ByteSequenceProperty.prop_id == prop_id).\
                                join(ByteSequence).\
                                join(Key).\
                                filter(Key.source_index_id == source_index_id).all()

    @staticmethod
    def get_keys_for_property_value(source_index_id, prop_val_id):
        """Returns all of the Keys with a particular property value from a particular
        source index."""
        return DB_SESSION.query(Key).join(ByteSequence).join(ByteSequenceProperty).\
                                filter(ByteSequenceProperty.prop_val_id == prop_val_id).\
                                filter(Key.source_index_id == source_index_id).all()

    @classmethod
    def putdate(cls, byte_sequence, format_tool, prop, prop_val):
        """Create or update the ByteSequenceProperty."""
        ret_val = cls.by_key_and_byte_sequence_id(byte_sequence.id, prop.id)
        if ret_val is None:
            ret_val = ByteSequenceProperty(byte_sequence, format_tool, prop, prop_val)
            ret_val.put()
        return ret_val

def init_db():
    """Initialise the database."""
    BASE.metadata.create_all(bind=ENGINE)
