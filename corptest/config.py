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
import os.path
import sys
import tempfile

from .const import ENV_CONF_PROFILE, ENV_CONF_FILE, JISC_BUCKET

HOST = 'localhost'

TEMP = tempfile.gettempdir()
HOME = os.path.expanduser('~')
LOG_ROOT = TEMP
class BaseConfig(object):# pylint: disable-msg=R0903
    """Base / default config, no debug logging and short log format."""
    NAME = 'Default'
    HOST = HOST
    DEBUG = False
    TESTING = False
    IS_FIDO = sys.version_info < (3, 0)
    LOG_FORMAT = '[%(filename)-15s:%(lineno)-5d] %(message)s'
    LOG_FILE = os.path.join(LOG_ROOT, 'jisc-rdss-format.log')
    SECRET_KEY = 'a5c020ced05af9ad3aacc6bba41beb5c7b6f750b846dadad'
    RDSS_ROOT = TEMP
    SQL_PATH = os.path.join(TEMP, 'jisc-rdss-format.db')
    SQL_URL = 'sqlite:///' + SQL_PATH
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FOLDERS = [
        {
            'name' : 'Temp File System',
            'description' : 'Example file based source using the temp directory.',
            'location' : TEMP
        }
    ]
    TOOLS = [
        {
            'namespace' : 'uk.gov.nationalarchives',
            'name' : 'DROID',
            'description' : 'Digital Record and Object Identication',
            'reference' :
            ''.join(['http://www.nationalarchives.gov.uk/information-management/',
                     'manage-information/preserving-digital-records/droid/'])
        },
        {
            'namespace' : 'org.openpreservation',
            'name' : 'FIDO',
            'description' : 'Format Identification for Digital Objects',
            'reference' : 'http://openpreservation.org/technology/products/fido/'
        },
        {
            'namespace' : 'com.darwinsys',
            'name' : 'File',
            'description' : 'The fine free file command.',
            'reference' : 'https://www.darwinsys.com/file/'
        },
        {
            'namespace' : 'org.python',
            'name' : 'python-magic',
            'description' : 'Python wrapping of the libmagic library.',
            'reference' : 'https://github.com/ahupp/python-magic/'
        },
        {
            'namespace' : 'org.apache',
            'name' : 'Tika',
            'description' : 'A content analysis toolkit.',
            'reference' : 'https://tika.apache.org/'
        }
    ]

class DevConfig(BaseConfig):# pylint: disable-msg=R0903
    """Developer level config, with debug logging and long log format."""
    NAME = 'Development'
    DEBUG = True
    TESTING = True
    LOG_FORMAT = '[%(levelname)-8s %(filename)-15s:%(lineno)-5d %(funcName)-30s] %(message)s'
    FOLDERS = [
        {
            'name' : 'Temp File System',
            'description' : 'Example file based source using the temp directory.',
            'location' : TEMP
        },
        {
            'name' : 'Home directory',
            'description' : 'The home folder of the user running this application.',
            'location' : HOME
        }
    ]
    BUCKETS = [
        {
            'name' : 'JISC Sample Bucket',
            'description' : 'JISC Research Data Shared Service Amazon S3 bucket.',
            'location' : JISC_BUCKET
        }
    ]

class TestConfig(BaseConfig):# pylint: disable-msg=R0903
    """Developer level config, with debug logging and long log format."""
    NAME = 'Testing'
    SQL_PATH = os.path.join(TEMP, 'test.db')
    SQL_URL = 'sqlite:///' + SQL_PATH

class VagrantConfig(DevConfig):# pylint: disable-msg=R0903
    """Vagrant config, with debug logging and long log format."""
    NAME = 'Vagrant'
    RDSS_ROOT = '/vagrant_data/'

CONFIGS = {
    "dev": 'corptest.config.DevConfig',
    "default": 'corptest.config.BaseConfig',
    "test": 'corptest.config.TestConfig',
    "vagrant": 'corptest.config.VagrantConfig'
}

def configure_app(app, profile_name='test'):
    """Grabs the environment variable for app config or defaults to dev."""
    if not profile_name:
        profile_name = 'test'
    config_name = os.getenv(ENV_CONF_PROFILE, profile_name)
    app.config.from_object(CONFIGS[config_name])
    if os.getenv(ENV_CONF_FILE):
        app.config.from_envvar(ENV_CONF_FILE)
