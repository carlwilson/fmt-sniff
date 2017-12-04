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
from json import dumps
import logging
from mimetypes import MimeTypes
import tempfile
try:
    from urllib.parse import unquote as unquote, quote as quote
except ImportError:
    from urllib import unquote as unquote, quote as quote

from botocore import exceptions
import dateutil.parser
import dicttoxml
from flask import render_template, send_file, request, make_response
from flask_negotiate import produces
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized

from .corptest import APP, __version__
from .database import DB_SESSION
from .model_sources import SCHEMES, Source, FormatToolRelease, SourceIndex, Key
from .model_properties import KeyProperty, Property, PropertyValue, ByteSequenceProperty
from .reporter import item_pdf_report, source_key_to_dict, report_to_dict, pdf_report
from .sources import SourceKey, FileSystem, AS3Bucket, BLOBSTORE
from .utilities import ObjectJsonEncoder, PrettyJsonEncoder
ROUTES = True

JSON_MIME = 'application/json'
PDF_MIME = 'application/pdf'
XML_MIME = 'text/xml'
@APP.route("/")
def home():
    """Application home page."""
    return render_template('home.html', buckets=Source.by_scheme(SCHEMES['AS3']),
                           folders=Source.by_scheme(SCHEMES['FILE']))

@APP.route("/source/<int:source_id>/folder/", defaults={'encoded_filepath': ''})
@APP.route('/source/<int:source_id>/folder/<path:encoded_filepath>/')
def list_folder(source_id, encoded_filepath):
    """Display the contents of a source folder."""
    try:
        return _folder_list(Source.by_id(source_id), encoded_filepath)
    except exceptions.NoCredentialsError:
        raise Unauthorized('No S3 credentials found.')

@APP.route("/source/<int:source_id>/file/<path:encoded_filepath>/")
def details_fs(source_id, encoded_filepath):
    """Display details of a source file."""
    try:
        return _file_details(Source.by_id(source_id), encoded_filepath)
    except exceptions.NoCredentialsError:
        raise Unauthorized('No S3 credentials found.')

@APP.route("/download/source/<source_id>/<path:encoded_filepath>/")
def download_fs(source_id, encoded_filepath):
    """Download a file from a source."""
    try:
        return _download_item(Source.by_id(source_id), encoded_filepath)
    except exceptions.NoCredentialsError:
        raise Unauthorized('No S3 credentials found.')

@APP.route("/api/analyse/<source_id>/<path:encoded_filepath>/")
@produces(JSON_MIME, XML_MIME, PDF_MIME)
def file_report(source_id, encoded_filepath):
    """Download a file from a source."""
    try:
        _fs, _key = _get_fs_and_key(Source.by_id(source_id), encoded_filepath, is_folder=False)
        if not _fs.key_exists(_key):
            raise NotFound('File %s not found' % encoded_filepath)
    except exceptions.NoCredentialsError:
        raise Unauthorized('No S3 credentials found.')

    key = _fs.get_key(unquote(encoded_filepath))
    _bs, bs_props = _fs.get_byte_sequence_properties(key)
    _add_byte_sequence_properties(_bs, bs_props)
    key.add_byte_sequence(_bs)
    if _request_wants_json():
        logging.debug("JSON file report for %s", key.value)
        return _json_file_report(key)
    elif _request_wants_xml():
        logging.debug("XML file report for %s", key.value)
        return _xml_file_report(key)
    logging.debug("PDF file report for %s", key.value)
    return _pdf_file_report(key)

def _json_file_report(key):
    response = APP.response_class(
        response=dumps(source_key_to_dict(key), cls=PrettyJsonEncoder),
        status=200,
        mimetype=JSON_MIME
    )
    return response

def _xml_file_report(key):
    xml = dicttoxml.dicttoxml(source_key_to_dict(key))
    response = APP.response_class(
        response=xml,
        status=200,
        mimetype=XML_MIME
    )
    return response

def _pdf_file_report(key):
    """Download a file from a source."""
    dest_name = ''
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        item_pdf_report(key, temp.name)
        dest_name = temp.name
        response = make_response(send_file(dest_name, mimetype=PDF_MIME))
        response.headers["Content-Disposition"] = \
            "attachment; " \
            "filename*=UTF-8''{quoted_filename}".format(
                quoted_filename=quote(key.name.encode('utf8'))
                )
        return response

@APP.route("/api/report/<report_id>/")
@produces(JSON_MIME, XML_MIME, PDF_MIME)
def full_report(report_id):
    """Download a full file system analysis report."""
    report = SourceIndex.by_id(report_id)
    if _request_wants_json():
        logging.debug("JSON file report for %s:%s", report.source.name, report.root_key)
        return _json_report(report)
    elif _request_wants_xml():
        logging.debug("XML file report for %s:%s", report.source.name, report.root_key)
        return _xml_report(report)
    logging.debug("PDF file report for %s:%s", report.source.name, report.root_key)
    return _pdf_report(report)


def _json_report(report):
    response = APP.response_class(
        response=dumps(report_to_dict(report)),
        status=200,
        mimetype=JSON_MIME
    )
    return response

def _xml_report(report):
    xml = dicttoxml.dicttoxml(report_to_dict(report))
    response = APP.response_class(
        response=xml,
        status=200,
        mimetype=XML_MIME
    )
    return response

def _pdf_report(report):
    """Download a file from a source."""
    dest_name = ''
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        pdf_report(report, temp.name)
        dest_name = temp.name
        response = make_response(send_file(dest_name, mimetype=PDF_MIME))
        response.headers["Content-Disposition"] = \
            "attachment; " \
            "filename*=UTF-8''{quoted_filename}".format(
                quoted_filename=quote(report.source.name)
                )
        return response

@APP.route("/tools/")
def tools():
    """Application tools listing"""
    return render_template('tool_config.html', tools=FormatToolRelease.all())

@APP.route("/blobstore/")
def blobstore():
    """Brief blobstore statistics"""
    return render_template('blobstore.html', blobstore=BLOBSTORE)

@APP.route("/tools/<int:tool_id>/", methods=['POST'])
def toggle_tool_enabed(tool_id):
    """POST method to toggle a tool on and off."""
    tool = FormatToolRelease.by_id(tool_id)
    tool.set_enabled(not tool.enabled)
    return dumps(tool.enabled, cls=ObjectJsonEncoder)

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
    analyse_sub_folders = request.form.get('analyse_sub_folders')
    logging.debug('encoded_filepath : %s', encoded_filepath)
    return _add_index(Source.by_id(source_id), encoded_filepath, analyse_sub_folders)

@APP.route("/reports/<int:report_id>/")
def report_detail(report_id):
    """Show the details of a report."""
    source_index = SourceIndex.by_id(report_id)
    size = source_index.size if source_index.size else 0
    file_count = source_index.key_count if source_index.key_count else 0
    return render_template('report_details.html', report=source_index,
                           file_count=file_count,
                           size=size,
                           key_props=KeyProperty.get_properties_for_index(report_id),
                           bs_props=ByteSequenceProperty.get_properties_for_index(report_id))

@APP.route("/reports/<int:report_id>/prop/<int:prop_id>/propval/<int:prop_val_id>")
def report_key_by_prop(report_id, prop_id, prop_val_id):
    """Show the details of a report."""
    source_index = SourceIndex.by_id(report_id)
    keys = KeyProperty\
        .get_keys_for_property_value(report_id, prop_val_id)
    logging.debug("Got %d Key properties", len(keys))
    if not keys:
        keys = ByteSequenceProperty\
            .get_keys_for_property_value(report_id, prop_val_id)
        logging.debug("Got %d Byte properties", len(keys))
    return render_template('files_by_prop.html', report=source_index,
                           file_count=source_index.key_count,
                           size=source_index.size,
                           keys=keys,
                           prop=Property.by_id(prop_id),
                           prop_val=PropertyValue.by_id(prop_val_id))

@APP.route("/reports/<int:report_id>/prop/<int:prop_id>")
def report_properties(report_id, prop_id):
    """Show the details of a report."""
    source_index = SourceIndex.by_id(report_id)
    prop_values = KeyProperty\
        .get_property_values_for_index(report_id, prop_id)
    if not prop_values:
        prop_values = ByteSequenceProperty\
            .get_property_values_for_index(report_id, prop_id)
    return render_template('report_property.html', report=source_index,
                           file_count=source_index.key_count,
                           size=source_index.size,
                           prop=Property.by_id(prop_id),
                           prop_values=prop_values)

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

@APP.errorhandler(Unauthorized)
def unauth_handler(unauthorized):
    """Basic not found request handler."""
    return render_template('401.html', unauthorized=unauthorized)

@APP.teardown_appcontext
def shutdown_session(exception=None):
    """Tear down the database session."""
    if exception:
        logging.warning("Shutting down database session with exception.")
    DB_SESSION.remove()

def _folder_list(source, encoded_filepath):
    _fs, filter_key = _get_fs_and_key(source, encoded_filepath)
    if not _fs.key_exists(filter_key):
        raise NotFound('Folder %s not found' % encoded_filepath)
    folders = _fs.list_folders(filter_key=filter_key)
    files = _fs.list_files(filter_key=filter_key)
    return render_template('folder_list.html', source=source, filter_key=filter_key,
                           properties=_fs.supported_properties, folders=folders, files=files)

def _add_index(source, encoded_filepath, analyse_sub_folders):
    _fs, filter_key = _get_fs_and_key(source, encoded_filepath)
    filter_key = filter_key if filter_key else SourceKey('')
    if not _fs.key_exists(filter_key):
        raise NotFound('Folder %s not found' % encoded_filepath)
    _index = SourceIndex(source, datetime.now(), filter_key.value)
    _index.put()
    for source_key in _fs.list_files(filter_key=filter_key, recurse=analyse_sub_folders):
        # get the full key and byte sequence properties
        full_source_key = _fs.get_key(source_key.value)
        _bs, bs_props = _fs.get_byte_sequence_properties(full_source_key)

        key = Key(_index, source_key.value, source_key.size,
                  dateutil.parser.parse(source_key.last_modified), byte_sequence=_bs)
        key.put()
        _add_key_properties(key, full_source_key.properties)
        _add_byte_sequence_properties(_bs, bs_props)
    return list_reports()

def _add_key_properties(key, properties):
    for prop_name in properties:
        db_prop = Property.putdate(prop_name)
        db_prop_val = PropertyValue.putdate(properties[prop_name])
        KeyProperty.putdate(key, db_prop, db_prop_val)

def _add_byte_sequence_properties(byte_sequence, properties):
    for format_tool_release in properties:
        logging.debug("ByteSequence property from tool: %s", format_tool_release)
        for prop_name in properties[format_tool_release]:
            db_prop = Property.putdate(prop_name)
            db_prop_val = PropertyValue.putdate(properties[format_tool_release][prop_name])
            ByteSequenceProperty.putdate(byte_sequence, format_tool_release, db_prop, db_prop_val)

def _file_details(source, encoded_filepath):
    _fs, _key = _get_fs_and_key(source, encoded_filepath, is_folder=False)
    if not _fs.key_exists(_key):
        raise NotFound('File %s not found' % encoded_filepath)
    key = _fs.get_key(unquote(encoded_filepath))
    _bs, bs_props = _fs.get_byte_sequence_properties(key)
    return render_template('file_details.html', source=source,
                           key=key, byte_sequence=_bs, bs_props=bs_props)

def _get_key_properties(source, encoded_filepath):
    _fs, key = _get_fs_and_key(source, encoded_filepath, is_folder=False)
    if not _fs.key_exists(key):
        raise NotFound('File %s not found' % encoded_filepath)
    return key, _fs.get_key_properties(key)

def _get_fs_and_key(source, encoded_filepath, is_folder=True):
    try:
        _fs = AS3Bucket(source) \
            if source.scheme == SCHEMES['AS3'] else FileSystem(source)
    except ValueError:
        raise NotFound('Could not find item %s in source %s' % encoded_filepath, source.name)
    path = unquote(encoded_filepath)
    key = SourceKey(path, is_folder) if path else None
    return _fs, key

def _download_item(source, encoded_filepath):
    _fs, key = _get_fs_and_key(source, encoded_filepath, is_folder=False)
    if not _fs.key_exists(key):
        raise NotFound('File %s not found' % encoded_filepath)
    temp_file, _ = _fs.get_path_and_byte_seq(key)
    mime_type = MimeTypes().guess_type(key.value)[0]
    response = make_response(send_file(temp_file, mimetype=mime_type))
    response.headers["Content-Disposition"] = \
        "attachment; " \
        "filename*=UTF-8''{quoted_filename}".format(
            quoted_filename=quote(key.name.encode('utf8'))
            )
    return response

def _request_wants_json():
    best = request.accept_mimetypes \
        .best_match([JSON_MIME, PDF_MIME])
    return best == JSON_MIME and \
        request.accept_mimetypes[best] > \
        request.accept_mimetypes[PDF_MIME]

def _request_wants_xml():
    best = request.accept_mimetypes \
        .best_match([XML_MIME, PDF_MIME])
    return best == XML_MIME and \
        request.accept_mimetypes[best] > \
        request.accept_mimetypes[PDF_MIME]

if __name__ == "__main__":
    APP.run(threaded=True)
