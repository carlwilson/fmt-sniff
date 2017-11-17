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
""" Package utilities: I/O, JSON and XML based mostly. """
from datetime import datetime
import errno
import hashlib
import json
import os.path
import requests

class ObjectJsonEncoder(json.JSONEncoder):
    """ Object JSON serialiser. """
    def default(self, o): # pylint: disable=E0202
        """ Custom Object JSON serialisation. """
        if isinstance(o, datetime):
            return {'__datetime__': o.replace(microsecond=0).isoformat()}
        return {'__{}__'.format(o.__class__.__name__): o.__dict__}

class PrettyJsonEncoder(json.JSONEncoder):
    """ Object JSON serialiser. """
    def default(self, o): # pylint: disable=E0202
        """ Custom Object JSON serialisation. """
        if isinstance(o, datetime):
            return o.replace(microsecond=0).isoformat()
        return {'{}'.format(o.__class__.__name__): o.__dict__}

def only_files(directory):
    """ Returns only the files in a directory. """
    onlyfiles = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    return onlyfiles

def create_dirs(dir_name):
    """ Method that creates the directory dir_name and parents but doesn't fail
    if the directory already exists.
    """
    try:
        # try making the parent dir
        os.makedirs(dir_name)
    except OSError as excep:
        # trap directory exists, that's OK, raise all others
        if excep.errno != errno.EEXIST:
            raise

def sha1_path(apath):
    """Return the SHA1 of the file at apath."""
    return _hashpath(apath, hashlib.sha1())

def _hashpath(apath, hasher):
    """Calculates the digest of the file at apath using the supplied hasher which
    should implement update(buffer) and hexdigest() methods.
    """
    with open(apath, 'rb') as afile:
        return _hashfile(afile, hasher)

def sha1_file(afile, blocksize=65536):
    """Calculates the SHA1 of afile."""
    return _hashfile(afile, hashlib.sha1(), blocksize)

def _hashfile(afile, hasher, blocksize=65536):
    """Calculates the digest of afile using the supplied hasher which should
    implement update(buffer) and hexdigest() methods.
    """
    buf = afile.read(blocksize)
    while buf:
        hasher.update(buf)
        buf = afile.read(blocksize)
    afile.seek(0)
    return hasher.hexdigest()

def sha1_string(astring):
    """Calculates the SHA1 of astring."""
    return _hashstring(astring, hashlib.sha1())

def _hashstring(astring, hasher):
    """Calculates the digest of astring using the supplied hasher which should
    implement update(buffer) and hexdigest() methods.
    """
    hasher.update(astring.encode('utf-8'))
    return hasher.hexdigest()

def sha1_copy_by_path(src_path, dest_path, blocksize=65536):
    """Copies a file from src_path to dest_path and calculates the SHA1 digest."""
    return _hash_copy_by_path(src_path, dest_path, hashlib.sha1(), blocksize=blocksize)

def _hash_copy_by_path(src_path, dest_path, hasher, blocksize=65536):
    """Copies a file from src_path to dest_path and calculates the digest using
    the supplied hasher which should implement update(buffer) and hexdigest() methods.
    """
    with open(src_path, 'rb') as src:
        with open(dest_path, 'wb') as dest:
            return _hash_copy_file(src, dest, hasher, blocksize=blocksize)

def sha1_copy_file(src, dest, blocksize=65536):
    """Copies a file from src to dest and calculates the SHA1 digest."""
    return _hash_copy_file(src, dest, hashlib.sha1(), blocksize=blocksize)

def _hash_copy_file(src, dest, hasher, blocksize=65536):
    """Copies a file from src to dest and calculates the digest using the supplied
    hasher which should implement update(buffer) and hexdigest() methods.
    """
    buf = src.read(blocksize)
    while buf:
        dest.write(buf)
        hasher.update(buf)
        buf = src.read(blocksize)
    return hasher.hexdigest()

def mapped_dict_from_element(root, parent_tags, tag_dict):
    """ Recursively parses an XML structure and maps tag names / tag values to the
    equivalent database field names. This info is stacked up in a dictionary that
    the fucntion returns.
    parent_tags: a list of tag values that are parents and should be recursed into
    tag_dict: a dictionary of tag-values that map to the database field name.
    """
    mapped_dict = dict()
    for child in root:
        child_tag = _strip_namespace(child.tag)
        # Parent element so recurse and merge the returned map
        if child_tag in parent_tags:
            child_dict = mapped_dict_from_element(child, parent_tags, tag_dict)
            mapped_dict.update(child_dict)
        # Mapped element, add the value to the returned dict
        elif child_tag in tag_dict:
            field = tag_dict[child_tag]
            mapped_dict[field] = child.text
    return mapped_dict

def _strip_namespace(name):
    """ Strips the namespace from a tag and returns the stripped tag. """
    if name[0] == "{":
        # If we have a namespace strip it and return the tag
        _, tag = name[1:].split("}")
        return tag
    return name

def sizeof_fmt(num, suffix='B'):
    """Format byte size in human readable form.
    from: http://stackoverflow.com/questions/1094841/reusable
    -library-to-get-human-readable-version-of-file-size
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)

def timestamp_fmt(timestamp, show_millis=True):
    """ISO format for timestamps."""
    format_str = "%Y-%m-%d %H:%M:%S.%f" if show_millis else "%Y-%m-%d %H:%M:%S"
    return timestamp.strftime(format_str)

def fill_file_from_response(source_url, temp_file):
    """HTTP get from source_url and writes the resoponse to temp_file"""
    # Grab the contents of the Amazon S3 bucket
    session = requests.Session()
    response = session.get(url=source_url)
    # Write response content and flush
    temp_file.write(response.content)
    temp_file.flush()
    # Reset temp for reading the XML
    temp_file.seek(0)

def check_param_not_none(param, name):
    """Check that the passed param is not None or an empty string.
    Raise a ValueError with the param's name if it is None or an empty string"""
    if not param:
        message_terminator = ' or an empty string.' if isinstance(param, str) else '.'
        raise ValueError("Argument {} can not be None{}".format(name, message_terminator))

class Extension(object):
    """Class for a file extenstion, the portion of a file name that follows the
    final period, "." in the file name.
    """
    def __init__(self, extension):
        self.__ext = extension

    @property
    def ext(self):
        """Return the extensions String value"""
        return self.__ext

    def is_json(self):
        """ Returns true if extension is JSON. """
        return self.__ext.lower() == 'json'

    @classmethod
    def from_file_name(cls, file_name):
        """ Creates a new extension instance by parsing file_name. """
        return cls(cls.parse_from_file_name(file_name))

    @staticmethod
    def parse_from_file_name(file_name):
        """Parses a string extension from a file name. """
        return os.path.splitext(file_name)[1][1:]
