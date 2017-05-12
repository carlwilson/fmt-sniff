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

# Get the appropriate config
configure_app(APP)
# Configure logging across all modules
logging.basicConfig(filename=APP.config['LOG_FILE'], level=logging.DEBUG,
                    format=APP.config['LOG_FORMAT'])
logging.info("Started JISC RDSS Format Identification app.")

from .database import init_db # pylint: disable-msg=C0413
logging.debug("Configured logging.")
logging.info("Initialising database.")
init_db()

if not APP.config['IS_FIDO']:
    logging.warning("Python %r doesn't allow for inline FIDO support.", sys.version_info)
else:
    logging.info("Python %r enables inline FIDO support.", sys.version_info)

from .model import AS3BucketSource, FileSystemSource, FormatTool # pylint: disable-msg=C0413
from .format_tools import get_format_tool_instance # pylint: disable-msg=C0413

BUCKET_LIST = APP.config.get('BUCKETS', {})
logging.info("Loading config BUCKETS to the bucket table")
for _bucket in BUCKET_LIST:
    if not AS3BucketSource.by_bucket_name(_bucket['location']):
        _bucket_item = AS3BucketSource(_bucket['name'], _bucket['description'],
                                       _bucket['location'])
        AS3BucketSource.add(_bucket_item)

FOLDER_LIST = APP.config.get('FOLDERS', {})
logging.info("Loading config FOLDERS the file_system table")
for _folder in FOLDER_LIST:
    if not FileSystemSource.by_name(_folder['name']):
        _fs_item = FileSystemSource(_folder['name'], _folder['description'], _folder['location'])
        FileSystemSource.add(_fs_item)

TOOL_LIST = APP.config.get('TOOLS', {})
logging.debug("Loading config TOOLS to the format_tools table")
TOOL_REG = []
for _tool in TOOL_LIST:
    if not FormatTool.by_name(_tool['name']):
        _tool_item = FormatTool(_tool['name'], _tool['description'], _tool['reference'])
        FormatTool.add(_tool_item)
    tool = FormatTool.by_name(_tool['name'])
    tool_version = get_format_tool_instance(tool)
    TOOL_REG.append(tool_version)

# Import the application routes
logging.info("Setting up application routes")
from .controller import ROUTES # pylint: disable-msg=W0403, W0611, C0413, C0411
