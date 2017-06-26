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
from datetime import datetime
import logging
from mimetypes import MimeTypes
try:
    from urllib.parse import unquote as unquote, quote as quote
except ImportError:
    from urllib import unquote as unquote, quote as quote

import dateutil.parser

from flask import render_template, send_file, jsonify, request, make_response
from werkzeug.exceptions import BadRequest, NotFound

from .corptest import APP, __version__
from .database import DB_SESSION
from .model import SCHEMES, Source, FormatToolRelease, SourceIndex, Key
from .model import ByteSequence, KeyProperties, Property
from .sources import SourceKey, FileSystem, AS3Bucket, BLOBSTORE
from .utilities import sizeof_fmt
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
    """Application tools listing"""
    return render_template('tool_config.html', tools=FormatToolRelease.all())

@APP.route("/blobstore/")
def blobstore():
    """Brief blobstore statistics"""
    return render_template('blobstore.html', blobstore=BLOBSTORE)

@APP.route("/tools/<int:tool_id>/", methods=['GET'])
def show_tool(tool_id):
    """Application tools configuration"""
    tool = FormatToolRelease.by_id(tool_id)
    logging.debug("Found tool %s", tool)
    return render_template('tool.html', tool=tool)

@APP.route("/tools/<int:tool_id>/", methods=['POST'])
def toggle_tool_enabed(tool_id):
    """POST method to toggle a tool on and off."""
    tool = FormatToolRelease.by_id(tool_id)
    enabled = tool.enabled
    logging.debug("Tool %s is %s", tool, enabled)
    if enabled:
        tool.disable()
    else:
        tool.enable()
    enabled = not tool.enabled
    logging.debug("Tool %s is %s", tool, enabled)
    return jsonify(enabled)

@APP.route("/reports/")
def list_reports():
    """Show the list of existing reports."""
    return render_template('report_list.html', reports=SourceIndex.all())

@APP.route("/reports/", methods=['POST'])
def new_report():
    """Kick off a new report"""
    source_id = request.form.get('source_id')
    logging.debug('source_id : %s', source_id)
    encoded_filepath = request.form.get('encoded_filepath')
    logging.debug('encoded_filepath : %s', encoded_filepath)
    return _add_index(Source.by_id(source_id), encoded_filepath)

@APP.route("/reports/<int:report_id>/")
def report_detail(report_id):
    """Show the details of a report."""
    source_index = SourceIndex.by_id(report_id)
    return render_template('report_details.html', report=source_index,
                           file_count=source_index.key_count,
                           size=sizeof_fmt(source_index.size),
                           props=KeyProperties.get_properties_for_index(report_id))

@APP.route("/reports/<int:report_id>/prop/<int:prop_id>")
def report_properties(report_id, prop_id):
    """Show the details of a report."""
    source_index = SourceIndex.by_id(report_id)
    return render_template('report_property.html', report=source_index,
                           file_count=source_index.key_count,
                           size=sizeof_fmt(source_index.size),
                           prop=Property.by_id(prop_id),
                           prop_values=KeyProperties\
                               .get_property_values_for_index(report_id, prop_id))

@APP.route("/about/")
def about():
    """Show the application about and config page"""
    return render_template('about.html', config=APP.config, version=__version__)

@APP.errorhandler(BadRequest)
def bad_request_handler(bad_request):
    """Basic bad request handler."""
    return "bad request %s" % bad_request

@APP.errorhandler(NotFound)
def not_found_handler(not_found):
    """Basic not found request handler."""
    return render_template('404.html', not_found=not_found)

@APP.teardown_appcontext
def shutdown_session(exception=None):
    """Tear down the database session."""
    if exception:
        logging.warning("Shutting down database session with exception.")
    DB_SESSION.remove()

def _folder_list(source_item, encoded_filepath):
    source, filter_key = _get_source_and_key(source_item, encoded_filepath)
    if not source.key_exists(filter_key):
        raise NotFound('Folder %s not found' % encoded_filepath)
    folders = source.list_folders(filter_key=filter_key)
    files = source.list_files(filter_key=filter_key)
    metadata_keys = source.metadata_keys()
    return render_template('folder_list.html', source_item=source_item, filter_key=filter_key,
                           metadata_keys=metadata_keys, folders=folders, files=files)

def _add_index(source_item, encoded_filepath):
    source, filter_key = _get_source_and_key(source_item, encoded_filepath)
    if not source.key_exists(filter_key):
        raise NotFound('Folder %s not found' % encoded_filepath)
    source_index = SourceIndex(source_item, datetime.now(), filter_key.value)
    source_index.put()
    for key in source.list_files(filter_key=filter_key, recurse=True):
        full_path, sha1 = source.get_temp_file(key)
        byte_seq = ByteSequence.by_sha1(sha1)
        logging.debug('byte_seq : %s', byte_seq)
        if byte_seq is None:
            byte_seq = ByteSequence.from_file(full_path)
            byte_seq.put()
        _source_key = Key(source_index, key.value, key.size,
                          dateutil.parser.parse(key.last_modified), byte_sequence=byte_seq)
        _source_key.put()
        source.get_file_properties(key, _source_key)
    return list_reports()

def _file_details(source_item, encoded_filepath):
    source, key = _get_source_and_key(source_item, encoded_filepath, is_folder=False)
    if not source.key_exists(key):
        raise NotFound('File %s not found' % encoded_filepath)
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
    if not source.key_exists(key):
        raise NotFound('File %s not found' % encoded_filepath)
    temp_file, _ = source.get_temp_file(key)
    mime_type = MimeTypes().guess_type(key.value)[0]
    response = make_response(send_file(temp_file, mimetype=mime_type))
    response.headers["Content-Disposition"] = \
        "attachment; " \
        "filename*=UTF-8''{quoted_filename}".format(
            quoted_filename=quote(key.name.encode('utf8'))
            )
    return response

if __name__ == "__main__":
    APP.run()
