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
"""Configuration for JISC RDSS format id Flask app."""
import os
import tempfile

from corptest.const import ENV_CONF_PROFILE, ENV_CONF_FILE, JISC_BUCKET

HOST = 'localhost'

TEMP = tempfile.gettempdir()
LOG_ROOT = TEMP
class BaseConfig(object):# pylint: disable-msg=R0903
    """Base / default config, no debug logging and short log format."""
    HOST = HOST
    DEBUG = False
    TESTING = False
    LOG_FORMAT = '[%(filename)-15s:%(lineno)-5d] %(message)s'
    LOG_FILE = os.path.join(LOG_ROOT, 'jisc-rdss-format.log')
    SECRET_KEY = 'a5c020ced05af9ad3aacc6bba41beb5c7b6f750b846dadad'
    RDSS_ROOT = TEMP
    SQL_URL = 'sqlite:////tmp/test.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FOLDERS = [
        {
            'name' : 'Example File Source',
            'description' : 'Example file based source using the temp directory.',
            'location' : TEMP
        }
    ]

class DevConfig(BaseConfig):# pylint: disable-msg=R0903
    """Developer level config, with debug logging and long log format."""
    DEBUG = True
    TESTING = True
    LOG_FORMAT = '[%(levelname)-8s %(filename)-15s:%(lineno)-5d %(funcName)-30s] %(message)s'
    RDSS_ROOT = '/vagrant_data/'
    BUCKETS = [
        {
            'name' : 'JISC Test Bucket',
            'description' : 'JISC Research Data Shared Service test Amazon S3 bucket.',
            'location' : JISC_BUCKET
        }
    ]

CONFIGS = {
    "dev": 'corptest.config.DevConfig',
    "default": 'corptest.config.BaseConfig'
}

def configure_app(app):
    """Grabs the environment variable for app config or defaults to dev."""
    config_name = os.getenv(ENV_CONF_PROFILE, 'dev')
    app.config.from_object(CONFIGS[config_name])
    if os.getenv(ENV_CONF_FILE):
        app.config.from_envvar(ENV_CONF_FILE)
