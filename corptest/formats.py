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
# Classes for modelling format information
import os, sys
import magic
from tika import detector
import tika
tika.TikaClientOnly = True
from fido import fido

class FormatTool(object):
    def __init__(self, name, version):
        self.name = name
        self.version = version

    def getName(self):
        return self.name

    def getVersion(self):
        return self.version

    def __str__(self):
        retVal = []
        retVal.append("FormatTool:[name=")
        retVal.append(self.name)
        retVal.append(", version=")
        retVal.append(self.version)
        retVal.append("]")
        return "".join(retVal)

class Extension(object):
    def __init__(self, extension):
        self.ext = extension

    def getExt(self):
        return self.ext

    @classmethod
    def fromFileName(cls, file_name):
        name, ext = os.path.splitext(file_name)
        return cls(ext[1:])

class MagicType(object):
    DELIM = ","
    MAGIC_IDENT = magic.Magic()
    def __init__(self, magic_string):
        self.format = magic_string.split(self.DELIM, 1)[0]
        self.qualifiers = magic_string.split(self.DELIM) if self.DELIM in magic_string else []
        if self.qualifiers:
            self.qualifiers.pop(0)

    def getFormat(self):
        return self.format

    def getQualifiers(self):
        return self.qualifiers

    def __str__(self):
        retVal = []
        retVal.append(self.format)
        if self.qualifiers:
            retVal.extend(self.qualifiers)
        return self.DELIM.join(retVal)

    @classmethod
    def fromFileByMagic(cls, file_to_id):
        magic_string = cls.MAGIC_IDENT.from_file(file_to_id)
        return cls(magic_string)

class PronomId(object):
    FIDO = fido.Fido(quiet=True)

    def __init__(self, puid, sig_name, mime):
        self.puid = puid
        self.sig = sig_name
        self.mime = mime

    def getPuid(self):
        return self.puid

    def getSig(self):
        return self.sig

    def getMime(self):
        return self.mime

    def __str__(self):
        retVal = []
        retVal.append("PronomId:[puid=")
        retVal.append(self.puid)
        retVal.append(", mime=")
        retVal.append(self.mime)
        retVal.append(", sig=")
        retVal.append(self.sig)
        retVal.append("]")
        return "".join(retVal)

    @classmethod
    def fromFileByFido(cls, file_to_id):
        retVal = []
        f = open(file_to_id, 'rb')
        size = os.stat(file_to_id)[6]
        bofbuffer, eofbuffer, _ = cls.FIDO.get_buffers(f, size, seekable=True)
        matches = cls.FIDO.match_formats(bofbuffer, eofbuffer)
        for (f, sig_name) in matches:
            mime = f.find('mime')
            mime_text = ""
            if mime is not None:
                mime_text = mime.text
            pronId = cls(cls.FIDO.get_puid(f), sig_name, mime_text)
            retVal.append(pronId)
        return retVal

class MimeType(object):
    PARAM_DELIM = ';'
    TYPE_DELIM = '/'
    MIME_IDENT = magic.Magic(mime=True)

    def __init__(self, mime_string):
        self.type, self.subtype = self.typesFromMimeString(mime_string)
        self.params = mime_string.split(self.PARAM_DELIM, 1)[1] if self.PARAM_DELIM in mime_string else ""

    def getType(self):
        return self.type

    def getSubType(self):
        return self.subtype

    def getParameters(self):
        return self.params

    def __str__(self):
        retVal = []
        retVal.append(self.type)
        retVal.append(self.TYPE_DELIM)
        retVal.append(self.subtype)
        if self.params:
            retVal.append(self.PARAM_DELIM)
            retVal.append(self.params)
        return "".join(retVal)

    @classmethod
    def fromFileByMagic(cls, file_to_id):
        mime_string = cls.MIME_IDENT.from_file(file_to_id)
        return cls(mime_string)

    @classmethod
    def fromFileByTika(cls, file_to_id):
        mime_string = detector.from_file(file_to_id)
        return cls(mime_string)

    @classmethod
    def typesFromMimeString(cls, mime_string):
        parts = mime_string.split(cls.PARAM_DELIM, 1)[0].split(cls.TYPE_DELIM, 1);
        return parts[0], parts[1]
