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
"""
JISC Research Data Shared Service : Format Indentification and analysis.

Initialisation module for package, kicks of the flask app.
"""
import logging
import sys
__version__ = '0.2.0'
__python_magic_version__ = '0.4.13'
__opf_fido_version__ = '1.3.5'
# Load the application
from flask import Flask
APP = Flask(__name__)

from .config import configure_app # pylint: disable-msg=C0413
from .utilities import sizeof_fmt, percent_fmt # pylint: disable-msg=C0413
# Get the appropriate config
configure_app(APP)
APP.jinja_env.globals.update(sizeof_fmt=sizeof_fmt) # pylint: disable-msg=E1101
APP.jinja_env.globals.update(percent_fmt=percent_fmt) # pylint: disable-msg=E1101

# Configure logging across all modules
logging.basicConfig(filename=APP.config['LOG_FILE'], level=logging.DEBUG,
                    format=APP.config['LOG_FORMAT'])
logging.info("Started JISC RDSS Format Identification app.")

from .model_sources import SCHEMES, get_property_from_bs # pylint: disable-msg=C0413
from .model_properties import init_db # pylint: disable-msg=C0413
APP.jinja_env.globals.update(get_property_from_bs=get_property_from_bs) # pylint: disable-msg=E1101

logging.debug("Configured logging.")
logging.info("Initialising database.")
init_db()

if not APP.config['IS_FIDO']:
    logging.warning("Python %r doesn't allow for inline FIDO support.", sys.version_info)
else:
    logging.info("Python %r enables inline FIDO support.", sys.version_info)

from .model_sources import Source, FormatTool, FormatToolRelease # pylint: disable-msg=C0413
from .format_tools import get_format_tool_instance # pylint: disable-msg=C0413
from .sources import AS3Bucket, FileSystem # pylint: disable-msg=C0413

BUCKET_LIST = APP.config.get('BUCKETS', {})
logging.info("Loading config BUCKETS to the bucket table")
for _bucket in BUCKET_LIST:
    logging.debug("Checking bucket: %s", _bucket)
    if not Source.by_location(_bucket['location']):
        _source = Source(AS3Bucket.NAMESPACE, _bucket['name'], _bucket['description'],
                         SCHEMES['AS3'], _bucket['location'])
        logging.debug("Adding bucket source: %s", _source)
        Source.add(_source)
    else:
        _source = Source.by_location(_bucket['location'])
        logging.debug("FOUND bucket source: %s", _source)

FOLDER_LIST = APP.config.get('FOLDERS', {})
logging.info("Loading config FOLDERS the file_system table")
for _folder in FOLDER_LIST:
    logging.debug("Checking folder: %s", _folder)
    if not Source.by_location(_folder['location']):
        _source = Source(FileSystem.NAMESPACE, _folder['name'], _folder['description'],
                         SCHEMES['FILE'], _folder['location'])
        logging.debug("Adding folder source: %s", _source)
        Source.add(_source)
    else:
        _source = Source.by_location(_folder['location'])
        logging.debug("FOUND folder source: %s", _source)

TOOL_LIST = APP.config.get('TOOLS', {})
logging.debug("Loading config TOOLS to the format_tools table")
for _tool in TOOL_LIST:
    logging.debug("Registering tool: %s, from tool list.", _tool)
    FormatTool.putdate(_tool['namespace'], _tool['name'], _tool['description'], _tool['reference'])

logging.debug("Setting all tools unavailable")
FormatToolRelease.all_unavailable()
for _tool in FormatTool.all():
    get_format_tool_instance(_tool)

# Import the application routes
logging.info("Setting up application routes")
from .controller import ROUTES # pylint: disable-msg=W0403, W0611, C0413, C0411
