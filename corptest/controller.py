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
""" Flask application routes for JISC RDSS format application. """
import logging
from mimetypes import MimeTypes
import ntpath
import urllib.parse
from flask import render_template, send_file
from corptest import APP
from corptest.database import DB_SESSION
from corptest.model import SourceDetails, SourceKey, AS3Bucket, FileSystem
from corptest.sources import FileSystemSource, AS3BucketSource

BUCKET_LIST = APP.config.get('BUCKETS', {})
if len(AS3Bucket.all()) < 1:
    logging.debug("Loading the bucket table")
    for _bucket in BUCKET_LIST:
        source_details = SourceDetails(_bucket['name'], _bucket['description'])
        _bucket_item = AS3Bucket(source_details, _bucket['location'])
        AS3Bucket.add(_bucket_item)
else:
    logging.debug("AS3Bucket has %i rows", len(AS3Bucket.all()))

FOLDER_LIST = APP.config.get('FOLDERS', {})
if len(FileSystem.all()) < 1:
    logging.debug("Loading the file_system table")
    for _folder in FOLDER_LIST:
        source_details = SourceDetails(_folder['name'], _folder['description'])
        _fs_item = FileSystem(source_details, _folder['location'])
        FileSystem.add(_fs_item)
else:
    logging.debug("FileSystem has %i rows", len(FileSystem.all()))

@APP.route("/")
def home():
    """Application home page."""
    return render_template('home.html', buckets=AS3Bucket.all(), folders=FileSystem.all())

@APP.route("/folder/<folder_id>/", defaults={'encoded_filepath': ''})
@APP.route('/folder/<folder_id>/<path:encoded_filepath>/')
def list_folder(folder_id, encoded_filepath):
    """Display the contents of a File System source folder."""
    return _list_source('folder', FileSystem.by_id(folder_id), encoded_filepath)

@APP.route("/bucket/<bucket_id>/", defaults={'encoded_filepath': ''})
@APP.route('/bucket/<bucket_id>/<path:encoded_filepath>/')
def list_bucket(bucket_id, encoded_filepath):
    """Display the contents of an AS3 source folder."""
    return _list_source('bucket', AS3Bucket.by_id(bucket_id), encoded_filepath)

@APP.route("/download/folder/<folder_id>/<path:encoded_filepath>/")
def download_fs(folder_id, encoded_filepath):
    """Download a file from a File System source."""
    return _download_item('folder', FileSystem.by_id(folder_id), encoded_filepath)

@APP.route("/download/bucket/<bucket_id>/<path:encoded_filepath>/")
def download_bucket(bucket_id, encoded_filepath):
    """Download a file from an AS3 source."""
    return _download_item('bucket', AS3Bucket.by_id(bucket_id), encoded_filepath)

@APP.teardown_appcontext
def shutdown_session(exception=None):
    """Tear down the database session."""
    if exception:
        logging.warning("Shutting down database session with exception.")
    DB_SESSION.remove()

def _list_source(source_type, source_item, encoded_filepath):
    source, filter_key = _get_source_and_key(source_type, source_item, encoded_filepath)
    folders = source.list_folders(filter_key=filter_key)
    files = source.list_files(filter_key=filter_key)
    return render_template('source_list.html', source_type=source_type,
                           source_item=source_item, folders=folders, files=files)

def _get_source_and_key(source_type, source_item, encoded_filepath, is_folder=True):
    source = AS3BucketSource(source_item) \
        if source_type == 'bucket' else FileSystemSource(source_item)
    path = urllib.parse.unquote(encoded_filepath)
    key = SourceKey(path, is_folder) if path else None
    return source, key

def _download_item(source_type, source_item, encoded_filepath):
    source, key = _get_source_and_key(source_type, source_item, encoded_filepath, is_folder=False)
    temp_file, _ = source.get_temp_file(key)
    mime_type = MimeTypes().guess_type(key.value)[0]
    return send_file(temp_file, mimetype=mime_type, as_attachment=True,
                     attachment_filename=ntpath.basename(key.value))

if __name__ == "__main__":
    APP.run()
