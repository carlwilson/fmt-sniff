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
""" Wrappers, serialisers and decoders for format identification tools. """
import collections
import os.path
import subprocess

import magic
from fido import fido


from .corptest import APP, __opf_fido_version__, __python_magic_version__
from .formats import MagicType, MimeType, PronomId

MIME_IDENT = magic.Magic(mime=True)
MAGIC_IDENT = magic.Magic()

class FineFreeFile(object):
    """The Fine Free File Command encapsulated"""
    __executions__ = {
        "version" : ['file', '--version'],
        "magic" : ['file'],
        "mime" : ['file', '--mime']
    }
    __version = None

    def __init__(self, format_tool):
        self.__version = self.__version if self.__version else self._get_version()
        self.__format_tool = format_tool

    @property
    def format_tool(self):
        """Return the associated FormatToolRelease."""
        return self.__format_tool

    @property
    def version(self):
        """Return the version number of the file utility."""
        return self.__version

    def identify(self, path):
        """"Runs the file utility on an individual file and returns the metadata."""
        if not path or not os.path.isfile(path):
            raise ValueError("Arg path must be an exisiting file.")
        if not self.version:
            return None
        metadata = {}
        cmd = list(self.__executions__['magic'])
        cmd.append(path)
        magic_res = subprocess.check_output(cmd, universal_newlines=True)
        magic_type = MagicType.from_magic_string(magic_res.split(':')[1])
        metadata['File MAGIC'] = magic_type
        cmd = list(self.__executions__['mime'])
        cmd.append(path)
        mime_res = subprocess.check_output(cmd, universal_newlines=True)
        mime_type = MimeType.from_mime_string(mime_res.split(':')[1])
        metadata['File MIME'] = \
            mime_type.get_short_string()
        return metadata

    @classmethod
    def _get_version(cls):
        try:
            proc_result = subprocess.check_output(cls.__executions__['version'],
                                                  universal_newlines=True)
        except OSError:
            # We're not supporting file here then
            return None
        return proc_result.splitlines()[0].split('-')[-1]

class DROID(object):
    """DROID encapsulated"""
    __executions__ = {
        "version" : ['droid', '-v'],
        "puid_1" : ['droid', '-Nr'],
        "puid_2" : ['-Ns',
                    '/usr/local/lib/tna-droid/DROID_SignatureFile_V88.xml',
                    '-Nc',
                    '/usr/local/lib/tna-droid/container-signature-20160927.xml'
                   ]
    }
    __version = None

    def __init__(self, format_tool):
        self.__version = self.__version if self.__version else self._get_version()
        self.__format_tool = format_tool

    @property
    def format_tool(self):
        """Return the associated FormatToolRelease."""
        return self.__format_tool

    @property
    def version(self):
        """Return the version number of the DROID tool."""
        return self.__version

    def identify(self, path):
        """Perform DROID identification."""
        if not path or not os.path.isfile(path):
            raise ValueError("Arg path must be an exisiting file.")
        if not self.version:
            return None
        metadata = {}
        cmd = list(self.__executions__['puid_1'])
        cmd.append(path)
        cmd.extend(self.__executions__['puid_2'])
        output = subprocess.check_output(cmd, universal_newlines=True)
        metadata['DROID PUID'] = output[output.rindex(',')+1:]
        return metadata

    @classmethod
    def _get_version(cls):
        try:
            proc_result = subprocess.check_output(cls.__executions__['version'],
                                                  universal_newlines=True)
        except OSError:
            # We're not supporting file here then
            return None
        return proc_result

class FIDO(object):
    """FIDO encapsulated"""
    FIDO = fido.Fido(quiet=True, nocontainer=True)
    __executions__ = {
    }
    __version = __opf_fido_version__ if APP.config['IS_FIDO'] else None

    def __init__(self, format_tool):
        self.__format_tool = format_tool

    @property
    def format_tool(self):
        """Return the associated FormatToolRelease."""
        return self.__format_tool

    @property
    def version(self):
        """Return the tool version string."""
        return self.__version

    def identify(self, path):
        """Perform FIDO identification."""
        if not path or not os.path.isfile(path):
            raise ValueError("Arg path must be an exisiting file.")
        if not self.version:
            return None
        metadata = {}
        fido_types = self._get_fido_types(path)
        if fido_types:
            pronom_result = fido_types[0]
            metadata['FIDO PUID'] = pronom_result.puid
            metadata['FIDO SIG'] = pronom_result.sig
            metadata['FIDO MIME'] = pronom_result.mime
        return metadata

    @classmethod
    def _get_fido_types(cls, path):
        retval = []
        size = os.stat(path).st_size
        fp_to_id = open(path, 'rb')
        bofbuffer, eofbuffer, _ = cls.FIDO.get_buffers(fp_to_id, size, seekable=True)
        matches = cls.FIDO.match_formats(bofbuffer, eofbuffer)
        for (sig, sig_name) in matches:
            mime = sig.find('mime')
            mime_text = ""
            if mime is not None:
                mime_text = mime.text
            pronom_id = PronomId(cls.FIDO.get_puid(sig), sig_name, mime_text)
            retval.append(pronom_id)
        return retval

class PythonMagic(object):
    """PythonMagic encapsulated"""
    __executions__ = {
        "version" : ['droid', '-v']
    }
    __version = __python_magic_version__

    def __init__(self, format_tool):
        self.__format_tool = format_tool

    @property
    def format_tool(self):
        """Return the associated FormatToolRelease."""
        return self.__format_tool

    @property
    def version(self):
        """Return the tool version string."""
        return self.__version

    def identify(self, path):
        """Perform Python Magic identification."""
        if not path or not os.path.isfile(path):
            raise ValueError("Arg path must be an exisiting file.")
        if not self.version:
            return None
        metadata = {}
        mime_string = MIME_IDENT.from_file(path)
        mime_type = MimeType.from_mime_string(mime_string)
        metadata['lib-magic MIME'] = mime_type.get_short_string()
        magic_string = MAGIC_IDENT.from_file(path)
        magic_type = MagicType.from_magic_string(magic_string)
        metadata['lib-magic MAGIC'] = magic_type
        return metadata

class Tika(object):
    """Tika encapsulated"""
    __executions__ = {
        "version" : ['tika', '--version']
    }
    __version = None

    def __init__(self, format_tool):
        self.__version = self.__version if self.__version else self._get_version()
        self.__format_tool = format_tool

    @property
    def format_tool(self):
        """Return the associated FormatToolRelease."""
        return self.__format_tool

    @property
    def version(self):
        """Return the version number of the file utility."""
        return self.__version

    def identify(self, path):
        """Perform Tika identification."""
        if not path or not os.path.isfile(path):
            raise ValueError("Arg path must be an exisiting file.")
        if not self.version:
            return None
        return None

    @classmethod
    def _get_version(cls):
        try:
            proc_result = subprocess.check_output(cls.__executions__['version'],
                                                  universal_newlines=True)
        except OSError:
            # We're not supporting file here then
            return None
        return proc_result.split(' ')[-1]

def get_format_tool_instance(format_tool):
    """Given an instance from the DB will find the right tool."""
    if format_tool.name.lower() == 'file':
        return FineFreeFile(format_tool)
    elif format_tool.name.lower() == 'droid':
        return DROID(format_tool)
    elif format_tool.name.lower() == 'fido':
        return FIDO(format_tool)
    elif format_tool.name.lower() == 'python-magic':
        return PythonMagic(format_tool)
    elif format_tool.name.lower() == 'apache tika':
        return Tika(format_tool)
    return None


RDSS_ROOT = APP.config.get('RDSS_ROOT')
RDSS_CACHE = os.path.join(RDSS_ROOT, 'cache')
MAGIC_DEFAULT = os.path.join(RDSS_CACHE, 'magic-blobs.out')
FILE_DEFAULT = os.path.join(RDSS_CACHE, 'file-blobs.out')
DROID_DEFAULT = os.path.join(RDSS_CACHE, 'droid-blobs.out')
TIKA_DEFAULT = os.path.join(RDSS_CACHE, 'tika-blobs.out')

class MagicLookup(object):
    """ Look up class for serialised file magic results. """
    def __init__(self, source_path=MAGIC_DEFAULT):
        self.source_path = source_path
        self.magic_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.magic_lookup)

    def get_magic_string(self, sha1):
        """ Retrieve and return a magic result by key. """
        return self.magic_lookup.get(sha1, None)

    @classmethod
    def load_from_file(cls, source_path=MAGIC_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        magic_lookup = collections.defaultdict(dict)
        for sha1, magic_string in file_by_line_split_generator(source_path):
            if not sha1 in magic_lookup:
                magic_lookup.update({sha1 : magic_string})
        return magic_lookup

class MimeLookup(object):
    """ Look up class for serialised file mime results. """
    def __init__(self, source_path=FILE_DEFAULT):
        self.source_path = source_path
        self.mime_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.mime_lookup)

    def get_mime_string(self, sha1):
        """ Retrieve and return MIME string by key. """
        return self.mime_lookup.get(sha1, None)

    @classmethod
    def load_from_file(cls, source_path=FILE_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        mime_lookup = collections.defaultdict(dict)
        for sha1, mime_string in file_by_line_split_generator(source_path):
            if not sha1 in mime_lookup:
                mime_lookup.update({sha1 : mime_string})
        return mime_lookup

class DroidLookup(object):
    """ Look up class for serialised droid results. """
    def __init__(self, source_path=DROID_DEFAULT):
        self.source_path = source_path
        self.puid_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.puid_lookup)

    def get_puid(self, key):
        """ Retrieve and return PUID string by key. """
        return self.puid_lookup.get(key, None)

    @classmethod
    def load_from_file(cls, source_path=DROID_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        puid_lookup = collections.defaultdict(dict)
        for sha1, puid in file_by_line_split_generator(source_path, ','):
            if not sha1 in puid_lookup:
                puid_lookup.update({sha1 : puid})
        return puid_lookup

class TikaLookup(object):
    """ Lookup class for Tika tika-ident pairs in serialised output. """
    def __init__(self, source_path=TIKA_DEFAULT):
        self.source_path = source_path
        self.mime_lookup = self.load_from_file(self.source_path)

    def get_entry_count(self):
        """ Return the number of entries in the lookup dict. """
        return len(self.mime_lookup)

    def get_mime_string(self, sha1):
        """ Retrieve and return MIME string by key. """
        return self.mime_lookup.get(sha1, None)

    @classmethod
    def load_from_file(cls, source_path=TIKA_DEFAULT):
        """ Clear and load the lookup table from the supplied or default source_path. """
        mime_lookup = collections.defaultdict(dict)
        for sha1, mime_string in file_by_line_split_generator(source_path):
            if not sha1 in mime_lookup:
                mime_lookup.update({sha1 : mime_string})
        return mime_lookup

def file_by_line_split_generator(path, splitter=':'):
    """ Convenience method to grab a file line by line. """
    with open(path) as src_file:
        for line in src_file:
            if splitter not in line:
                continue
            parts = line.split(splitter)
            yield _get_sha1_from_path(parts[0].strip()), parts[1][:-1].strip()

def _get_sha1_from_path(path_str):
    """ Parse the SHA1 from any BlobStore path. """
    return path_str.rpartition('/')[2]
