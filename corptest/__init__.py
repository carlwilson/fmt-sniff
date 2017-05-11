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
from os.path import abspath, dirname, join
import sys
__version__ = '0.2.0'
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
# Load the application
APP = Flask(__name__)
CONFIG_DIR = join(abspath(dirname(__file__)), 'conf')
from corptest.config import configure_app
# Get the appropriate config
configure_app(APP)

# Configure logging across all modules
logging.basicConfig(filename=APP.config['LOG_FILE'], level=logging.DEBUG,
                    format=APP.config['LOG_FORMAT'])
logging.info("Started JISC RDSS Format Identification app.")
logging.debug("Configured logging.")
logging.info("Initialising database.")
if not APP.config['IS_FIDO']:
    logging.warning("Python %r doesn't allow for inline FIDO support.", sys.version_info)
else:
    logging.info("Python %r enables inline FIDO support.", sys.version_info)

from corptest.database import init_db
init_db()

# Import the application routes
import corptest.controller# pylint: disable-msg=C0413
logging.info("Setting up application routes")
