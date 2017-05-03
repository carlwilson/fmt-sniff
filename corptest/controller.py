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
from mimetypes import MimeTypes
import ntpath
import urllib.parse
from flask import render_template, send_file
from corptest import APP
from corptest.sources import SourceDetails, SourceKey, FileSystemSource, AS3BucketSource

BUCKETS = {b['id'] : b for b in APP.config['BUCKETS']}
FOLDERS = {f['id'] : f for f in APP.config['FOLDERS']}

@APP.route("/")
def home():
    """Application home page."""
    return render_template('home.html', buckets=BUCKETS.values(), folders=FOLDERS.values())

@APP.route("/folder/<folder_id>/", defaults={'encoded_filepath': ''})
@APP.route('/folder/<folder_id>/<path:encoded_filepath>/')
def list_folder(folder_id, encoded_filepath):
    return list_source('folder', FOLDERS[folder_id], encoded_filepath)

@APP.route("/bucket/<bucket_id>/", defaults={'encoded_filepath': ''})
@APP.route('/bucket/<bucket_id>/<path:encoded_filepath>/')
def list_bucket(bucket_id, encoded_filepath):
    return list_source('bucket', BUCKETS[bucket_id], encoded_filepath)

@APP.route("/download/folder/<folder_id>/<path:encoded_filepath>/")
def download_fs(folder_id, encoded_filepath):
    return download_item('folder', FOLDERS[folder_id], encoded_filepath)

@APP.route("/download/bucket/<bucket_id>/<path:encoded_filepath>/")
def download_bucket(bucket_id, encoded_filepath):
    return download_item('bucket', BUCKETS[bucket_id], encoded_filepath)

def list_source(source_type, source_item, encoded_filepath):
    source, filter_key = get_source_and_key(source_type, source_item, encoded_filepath)
    folders = source.list_folders(filter_key=filter_key)
    files = source.list_files(filter_key=filter_key)
    return render_template('source_list.html', source_type=source_type,
                           source_item=source_item, folders=folders, files=files)

def get_source_and_key(source_type, source_item, encoded_filepath, is_folder=True):
    details = details_from_config_item(source_item)
    source = AS3BucketSource(details, source_item['location'])\
        if source_type == 'bucket' else FileSystemSource(details, source_item['location'])
    path = urllib.parse.unquote(encoded_filepath)
    key = SourceKey(path, is_folder) if path else None
    return source, key

def details_from_config_item(item):
    details = SourceDetails(item['name'], item['description'])
    return details

def download_item(source_type, source_item, encoded_filepath):
    source, key = get_source_and_key(source_type, source_item, encoded_filepath, is_folder=False)
    temp_file, _ = source.get_temp_file(key)
    mime_type =  MimeTypes().guess_type(key.value)[0]
    return send_file(temp_file, mimetype=mime_type, as_attachment=True,
                     attachment_filename=ntpath.basename(key.value))

if __name__ == "__main__":
    APP.run()
