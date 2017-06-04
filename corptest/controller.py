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
try:
    from urllib.parse import unquote as unquote
except ImportError:
    from urllib import unquote as unquote

from flask import render_template, send_file
from .corptest import APP, __version__, TOOL_REG
from .database import DB_SESSION
from .model import SCHEMES, Source
from .sources import SourceKey, FileSystem, AS3Bucket
ROUTES = True

@APP.route("/")
def home():
    """Application home page."""
    return render_template('home.html', buckets=Source.by_scheme(SCHEMES['AS3']),
                           folders=Source.by_scheme(SCHEMES['FILE']))

@APP.route("/source/<int:source_id>/folder/", defaults={'encoded_filepath': ''})
@APP.route('/source/<int:source_id>/folder/<path:encoded_filepath>/')
def list_folder(source_id, encoded_filepath):
    """Display the contents of a source folder."""
    return _folder_list(Source.by_id(source_id), encoded_filepath)

@APP.route("/source/<int:source_id>/file/<path:encoded_filepath>/")
def details_fs(source_id, encoded_filepath):
    """Display details of a source file."""
    return _file_details(Source.by_id(source_id), encoded_filepath)

@APP.route("/download/source/<source_id>/<path:encoded_filepath>/")
def download_fs(source_id, encoded_filepath):
    """Download a file from a source."""
    return _download_item(Source.by_id(source_id), encoded_filepath)

@APP.route("/tools/")
def tools():
    """Application tools configuration"""
    return render_template('tool_config.html', tools=TOOL_REG)

@APP.route("/tools/<int:tool_id>/")
def show_tool(tool_id):
    """Application tools configuration"""
    for tool_inst in TOOL_REG.values():
        logging.debug("Tool reg contains %s", tool_inst)
    tool = TOOL_REG.get(tool_id)
    logging.debug("Found tool %s", tool)
    return render_template('tool.html', tool=tool)

@APP.route("/about/")
def about():
    """Show the application about and config page"""
    return render_template('about.html', config=APP.config, version=__version__)

@APP.teardown_appcontext
def shutdown_session(exception=None):
    """Tear down the database session."""
    if exception:
        logging.warning("Shutting down database session with exception.")
    DB_SESSION.remove()

def _folder_list(source_item, encoded_filepath):
    source, filter_key = _get_source_and_key(source_item, encoded_filepath)
    folders = source.list_folders(filter_key=filter_key)
    files = source.list_files(filter_key=filter_key)
    metadata_keys = source.metadata_keys()
    return render_template('folder_list.html', source_item=source_item, filter_key=filter_key,
                           metadata_keys=metadata_keys, folders=folders, files=files)

def _file_details(source_item, encoded_filepath):
    source, key = _get_source_and_key(source_item, encoded_filepath, is_folder=False)
    enhanced_key = source.get_file_metadata(key)
    return render_template('file_details.html', source_item=source_item,
                           enhanced_key=enhanced_key)

def _get_source_and_key(source_item, encoded_filepath, is_folder=True):
    source = AS3Bucket(source_item) \
        if source_item.scheme == SCHEMES['AS3'] else FileSystem(source_item)
    path = unquote(encoded_filepath)
    key = SourceKey(path, is_folder) if path else None
    return source, key

def _download_item(source_item, encoded_filepath):
    source, key = _get_source_and_key(source_item, encoded_filepath, is_folder=False)
    temp_file, _ = source.get_temp_file(key)
    mime_type = MimeTypes().guess_type(key.value)[0]
    return send_file(temp_file, mimetype=mime_type, as_attachment=True,
                     attachment_filename=ntpath.basename(key.value))

if __name__ == "__main__":
    APP.run()
