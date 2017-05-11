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
import collections
import os
import subprocess

import magic
from fido import fido

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
        ret_val.append("FormatTool : [name=")
        ret_val.append(self.name)
        ret_val.append(", version=")
        ret_val.append(self.version)
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for FormatTool. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            tool = obj[cls_name]
            return cls(tool['name'], tool['version'])
        return obj

class MagicType(object):
    """Class to model a "magic" type, returned from libmagic or the file
    utility
    """
    DELIM = ","
    MAGIC_IDENT = magic.Magic()
    def __init__(self, format_name, qualifiers):
        self.format_name = format_name
        self.qualifiers = qualifiers

    def get_format_name(self):
        """Returns the format identifier from the magic type"""
        return self.format_name

    def get_qualifiers(self):
        """Returns any qualifers parsed from the magic type"""
        return self.qualifiers

    def __str__(self):
        ret_val = []
        ret_val.append(self.format_name)
        if self.qualifiers:
            ret_val.extend(self.qualifiers)
        return self.DELIM.join(ret_val)

    @classmethod
    def get_default(cls):
        """ Return the default instance. """
        return cls("Unknown", [])

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for FormatTool. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            magic_type = obj[cls_name]
            return cls(magic_type['format_name'], magic_type['qualifiers'])
        return obj

    @classmethod
    def from_file_by_magic(cls, file_to_id):
        """Returns the libmagic format id for file_to_id"""
        magic_string = cls.MAGIC_IDENT.from_file(file_to_id)
        return cls.from_magic_string(magic_string)

    @classmethod
    def from_file_by_file(cls, file_to_id):
        """"Runs the file utility on an individual file and returns the MIME type."""
        mime_result = subprocess.check_output(['file', file_to_id], universal_newlines=True)
        return cls.from_magic_string(mime_result.split(':')[1])

    @classmethod
    def from_magic_string(cls, magic_string):
        """ Creates an new instance from a raw magic string. """
        format_name = magic_string.split(cls.DELIM, 1)[0]
        qualifiers = magic_string.split(cls.DELIM) if cls.DELIM in magic_string else []
        if qualifiers:
            qualifiers.pop(0)
        return cls(format_name, qualifiers)

class PronomId(object):
    """Models PRONOM unique identifiers, or PUIDs and their attributes"""
    FIDO = fido.Fido(quiet=True, nocontainer=True)
    PUIDS = collections.defaultdict(dict)

    def __init__(self, puid, sig_name, mime):
        self.puid = puid
        self.sig = "Unknown" if sig_name is None else sig_name
        self.mime = str(MimeType.get_default()) if mime is None else mime

    def get_puid(self):
        """The PUID's String value"""
        return self.puid

    def get_sig(self):
        """The signature for this PRONOM ID"""
        return self.sig

    def get_mime(self):
        """Returns the MIME type associated with the PRONOM ID"""
        return self.mime

    @classmethod
    def get_default(cls):
        """ Return the default instance. """
        return cls("Unknown", "Unknown", str(MimeType.get_default()))

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
    def json_decode(cls, obj):
        """ Custom JSON decoder for FormatTool. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            pronom_type = obj[cls_name]
            return cls(pronom_type['puid'], pronom_type['sig'], pronom_type['mime'])
        return obj

    @classmethod
    def initialise(cls):
        """ Load the puid info lookup from Fidos sig utilities. """
        cls.PUIDS = collections.defaultdict(dict)
        pron_id = PronomId.get_default()
        cls.PUIDS.update({pron_id.puid : pron_id})
        for form in cls.FIDO.formats:
            puid = cls.FIDO.get_puid(form)
            mime = form.find('mime')
            mime_text = None
            if not mime is None:
                mime_text = mime.text
            sig_name_text = None
            for sig in cls.FIDO.get_signatures(form):
                sig_name = sig.find('name')
                if not sig_name is None:
                    sig_name_text = sig_name.text
            pron_id = PronomId(puid, sig_name_text, mime_text)
            cls.PUIDS.update({puid : pron_id})

    @classmethod
    def get_pronom_type(cls, puid):
        """ Lookup and return a PronomId by puid. """
        return cls.PUIDS.get(puid, None)

    @classmethod
    def from_file_by_fido(cls, file_to_id):
        """Uses FIDO to identify file_to_id and returns the PronomId"""
        ret_val = []
        size = os.stat(file_to_id).st_size
        fp_to_id = open(file_to_id, 'r')
        bofbuffer, eofbuffer, _ = cls.FIDO.get_buffers(fp_to_id, size, seekable=True)
        matches = cls.FIDO.match_formats(bofbuffer, eofbuffer)
        for (sig, sig_name) in matches:
            mime = sig.find('mime')
            mime_text = ""
            if mime is not None:
                mime_text = mime.text
            pronom_id = cls(cls.FIDO.get_puid(sig), sig_name, mime_text)
            ret_val.append(pronom_id)
        return ret_val

    @classmethod
    def from_file_by_droid(cls, file_to_id):
        """Get PUID from file using command line DROID."""
        command = [
            'droid',
            '-Nr',
            file_to_id,
            '-Ns',
            '/usr/local/lib/tna-droid/DROID_SignatureFile_V88.xml',
            '-Nc',
            '/usr/local/lib/tna-droid/container-signature-20160927.xml'
        ]
        output = subprocess.check_output(command, universal_newlines=True)
        return output[output.rindex(',')+1:]

class MimeType(object):
    """Models internet MIME identifiers"""
    PARAM_DELIM = ';'
    TYPE_DELIM = '/'
    MIME_IDENT = magic.Magic(mime=True)

    def __init__(self, main_type, subtype, params):
        self.type = main_type
        self.subtype = subtype
        self.params = params

    def get_type(self):
        """Returns the MIME "type" portion of the identifier"""
        return self.type

    def get_sub_type(self):
        """Returns the MIME "sub-type" portion of the identifier"""
        return self.subtype

    def get_parameters(self):
        """Returns any parameters for the MIME id"""
        return self.params

    def get_short_string(self):
        """ Returns the MIME short string (without params and the like). """
        ret_val = []
        ret_val.append(self.type)
        ret_val.append(self.TYPE_DELIM)
        ret_val.append(self.subtype)
        return "".join(ret_val)

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
    def get_default(cls):
        """ Return the default instance. """
        return cls.from_mime_string("application/octet-stream")

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for FormatTool. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            mime_type = obj[cls_name]
            return cls(mime_type['type'], mime_type['subtype'], mime_type['params'])
        return obj

    @classmethod
    def from_file_by_magic(cls, file_to_id):
        """Creates a new MimeType instance by identifying file_to_id"""
        mime_string = cls.MIME_IDENT.from_file(file_to_id)
        return cls.from_mime_string(mime_string)

    @classmethod
    def from_mime_string(cls, mime_string):
        """ Creates a new MimeType instance parsed from mime_string. """
        main_type, subtype = cls.types_from_mime_string(mime_string)
        params = mime_string.split(cls.PARAM_DELIM, 1)[1] \
            if cls.PARAM_DELIM in mime_string else ""
        return cls(main_type, subtype, params)

    @classmethod
    def types_from_mime_string(cls, mime_string):
        """Splits the type and sub-type parts of a MIME string"""
        parts = mime_string.split(cls.PARAM_DELIM, 1)[0].split(cls.TYPE_DELIM, 1)
        return parts[0], parts[1]

    @classmethod
    def from_file_by_file(cls, file_to_id):
        """"Runs the file utility on an individual file and returns the MIME type."""
        mime_result = subprocess.check_output(['file', '-i', file_to_id], universal_newlines=True)
        return cls.from_mime_string(mime_result.split(':')[1])

class ToolResult(object):
    """ Class encapsulating tool results. """
    def __init__(self, tool, mime_result, magic_result, pronom_result):
        self.tool = tool
        self.mime_result = mime_result
        self.magic_result = magic_result
        self.pronom_result = pronom_result

    def get_tool(self):
        """ Return the tool details. """
        return self.tool

    def get_mime_result(self):
        """ Return the mime result. """
        return self.mime_result

    def get_magic_result(self):
        """ Return the magic result. """
        return self.magic_result

    def get_pronom_result(self):
        """ Return the PRONOM result. """
        return self.pronom_result

    def __str__(self):
        ret_val = []
        ret_val.append("ToolResult : [tool=")
        ret_val.append(str(self.tool))
        ret_val.append(", mime=")
        ret_val.append(str(self.mime_result))
        ret_val.append(", magic=")
        ret_val.append(str(self.magic_result))
        ret_val.append(", pronom=")
        ret_val.append(str(self.pronom_result))
        ret_val.append("]")
        return "".join(ret_val)

    @classmethod
    def json_decode(cls, obj):
        """ Custom JSON decoder for FormatTool. """
        cls_name = '__{}__'.format(cls.__name__)
        if cls_name in obj:
            tool_res = obj[cls_name]
            return cls(ToolResult.json_decode(tool_res['tool']),
                       MimeType.json_decode(tool_res['mime_result']),
                       MagicType.json_decode(tool_res['magic_result']),
                       PronomId.json_decode(tool_res['pronom_result']))
        return obj
