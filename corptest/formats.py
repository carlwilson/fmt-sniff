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
"""Classes for modelling format information"""
import os
from fido import fido
import magic
from tika import detector
import tika
tika.TikaClientOnly = True

class FormatTool(object):
    """Class to hold the details of a format identification tool."""
    def __init__(self, name, version):
        self.name = name
        self.version = version

    def get_name(self):
        """Returns the recognised name of the format tool"""
        return self.name

    def get_version(self):
        """Returns the software version of the format tool."""
        return self.version

    def __str__(self):
        ret_val = []
        ret_val.append("FormatTool:[name=")
        ret_val.append(self.name)
        ret_val.append(", version=")
        ret_val.append(self.version)
        ret_val.append("]")
        return "".join(ret_val)

class Extension(object):
    """Class for a file extenstion, the portion of a file name that follows the
    final period, "." in the file name.
    """
    def __init__(self, extension):
        self.ext = extension

    def get_ext(self):
        """Return the extensions String value"""
        return self.ext

    @classmethod
    def from_file_name(cls, file_name):
        """Creates a new extension instance by parsing file_name"""
        name, ext = os.path.splitext(file_name)
        return cls(ext[1:])

class MagicType(object):
    """Class to model a "magic" type, returned from libmagic or the file
    utility
    """
    DELIM = ","
    MAGIC_IDENT = magic.Magic()
    def __init__(self, magic_string):
        self.format = magic_string.split(self.DELIM, 1)[0]
        self.qualifiers = magic_string.split(self.DELIM) if self.DELIM in magic_string else []
        if self.qualifiers:
            self.qualifiers.pop(0)

    def get_format(self):
        """Returns the format identifier from the magic type"""
        return self.format

    def get_qualifiers(self):
        """Returns any qualifers parsed from the magic type"""
        return self.qualifiers

    def __str__(self):
        ret_val = []
        ret_val.append(self.format)
        if self.qualifiers:
            ret_val.extend(self.qualifiers)
        return self.DELIM.join(ret_val)

    @classmethod
    def from_file_by_magic(cls, file_to_id):
        """Returns the libmagic format id for file_to_id"""
        magic_string = cls.MAGIC_IDENT.from_file(file_to_id)
        return cls(magic_string)

class PronomId(object):
    """Models PRONOM unique identifiers, or PUIDs and their attributes"""
    FIDO = fido.Fido(quiet=True)

    def __init__(self, puid, sig_name, mime):
        self.puid = puid
        self.sig = sig_name
        self.mime = mime

    def get_puid(self):
        """The PUID's String value"""
        return self.puid

    def get_sig(self):
        """The signature for this PRONOM ID"""
        return self.sig

    def get_mime(self):
        """Returns the MIME type associated with the PRONOM ID"""
        return self.mime

    def __str__(self):
        ret_val = []
        ret_val.append("PronomId:[puid=")
        ret_val.append(self.puid)
        ret_val.append(", mime=")
        ret_val.append(self.mime)
        ret_val.append(", sig=")
        ret_val.append(self.sig)
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def from_file_by_fido(cls, file_to_id):
        """Uses FIDO to identify file_to_id and returns the PronomId"""
        ret_val = []
        file_to_id = open(file_to_id, 'rb')
        size = os.stat(file_to_id)[6]
        bofbuffer, eofbuffer, _ = cls.FIDO.get_buffers(file_to_id, size, seekable=True)
        matches = cls.FIDO.match_formats(bofbuffer, eofbuffer)
        for (sig, sig_name) in matches:
            mime = sig.find('mime')
            mime_text = ""
            if mime is not None:
                mime_text = mime.text
            pronom_id = cls(cls.FIDO.get_puid(sig), sig_name, mime_text)
            ret_val.append(pronom_id)
        return ret_val

class MimeType(object):
    """Models internet MIME identifiers"""
    PARAM_DELIM = ';'
    TYPE_DELIM = '/'
    MIME_IDENT = magic.Magic(mime=True)

    def __init__(self, mime_string):
        self.type, self.subtype = self.types_from_mime_string(mime_string)
        self.params = mime_string.split(self.PARAM_DELIM, 1)[1] \
            if self.PARAM_DELIM in mime_string else ""

    def get_type(self):
        """Returns the MIME "type" portion of the identifier"""
        return self.type

    def get_sub_type(self):
        """Returns the MIME "sub-type" portion of the identifier"""
        return self.subtype

    def get_parameters(self):
        """Returns any parameters for the MIME id"""
        return self.params

    def __str__(self):
        ret_val = []
        ret_val.append(self.type)
        ret_val.append(self.TYPE_DELIM)
        ret_val.append(self.subtype)
        if self.params:
            ret_val.append(self.PARAM_DELIM)
            ret_val.append(self.params)
        return "".join(ret_val)

    @classmethod
    def from_file_by_magic(cls, file_to_id):
        """Creates a new MimeType instance by identifying file_to_id"""
        mime_string = cls.MIME_IDENT.from_file(file_to_id)
        return cls(mime_string)

    @classmethod
    def from_file_by_tika(cls, file_to_id):
        """Creates a new MimeType instance using Tika on file_to_id"""
        mime_string = detector.from_file(file_to_id)
        return cls(mime_string)

    @classmethod
    def types_from_mime_string(cls, mime_string):
        """Splits the type and sub-type parts of a MIME string"""
        parts = mime_string.split(cls.PARAM_DELIM, 1)[0].split(cls.TYPE_DELIM, 1)
        return parts[0], parts[1]
