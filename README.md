Research Data Format Identification
===================================
*Web front end for file format identification and analysis*

[![Build Status](https://travis-ci.org/carlwilson/fmt-sniff.svg?branch=master)](https://travis-ci.org/carlwilson/fmt-sniff "Travis-CI integration build")
[![CodeCov Coverage](https://img.shields.io/codecov/c/github/carlwilson/fmt-sniff.svg)](https://codecov.io/gh/carlwilson/fmt-sniff/ "CodeCov test coverage figure")
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ab34b42c50954e4192987e060321ea17)](https://www.codacy.com/app/openpreserve/fmt-sniff?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=carlwilson/fmt-sniff&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/ab34b42c50954e4192987e060321ea17)](https://www.codacy.com/app/openpreserve/fmt-sniff?utm_source=github.com&utm_medium=referral&utm_content=carlwilson/fmt-sniff&utm_campaign=Badge_Coverage)

Description
-----------
The `fmt-sniff` project provides a set of Python tools that test format
identification tools across a data corpus and reports the results. A generalised
workflow is:

1. Declare a corpus soruce, either an Amazon S3 bucket or a local file system.
2. If the corpus is an S3 instance the data will be downloaded to a local cache.
3. The tool then runs the following format identification tools across the corpus:
  - [file command](https://www.darwinsys.com/file/) if installed locally;
  - [python-magic](https://pypi.python.org/pypi/python-magic) v0.4.12 the
python library based upon the file library;
  - [DROID](http://www.nationalarchives.gov.uk/information-management/manage-information/preserving-digital-records/droid/) v6.3 with [Signature File v88](http://www.nationalarchives.gov.uk/documents/DROID_SignatureFile_V88.xml)
and [Container Sigs 27/09/2016](http://www.nationalarchives.gov.uk/documents/container-signature-20160927.xml);
  - [FIDO](http://openpreservation.org/technology/products/fido/) v1.3.5; and
  - [Apache Tika](https://tika.apache.org/) v1.14.
4. Aggregate data and produce a statistical analysis of the results, including:
  - distribution of file sizes;
  - distribution of file formats;
  - discrepancies between identification results of tools; and
  - breakdown of results by institutional dataset.
5. Publish the report to an Amazon S3 endpoint.

Quick Start
-----------
### Pre-requisites
- Python3
- Any linux distro although the provided [install script](./scripts/setup.sh) is debian flavour specific as it uses `apt`.

### Dependencies
The setup script uses `apt` to install the following packages:
  - `openjdk-7-jre` for running DROID and Tika;
  - `libxml2-dev` for Python XML support;
  - `libxslt1-dev` for Python XSLT support;
  - `python3-dev` development headers for Python 3; and
  - `python-dev` for compiling / installing Python dependencies;
  - `unzip` to unpack the DROID download;
  - `virtualenv` for isolated Python development environment.
  - `zlib1g-dev` C libraries and headers for Python C libraries;

After installing the dependencies above provided [setup script](./scripts/setup.sh) then downloads and installs DROID and Tika. It also creates convenient shell scripts and symlinks to make running the tool easier.

Finally it creates a [Python virtal environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) beneath the users home directory, `~/.venvs/fmt-sniff` and installs the Python dependencies from the [PIP requirements file](./requirements.txt). These include
the Amazon S3 API and the python-magic and FIDO tools which are Python based.

### Installation
#### Vagrant virtual machine
The easiest and safest way to install and test the software is to use
[Vagrant](https://www.vagrantup.com/) which automates the setup of virtual machines. The provided [Vagrantfile](./Vagrantfile) describes a suitable machine
and runs the required setup script. In order to get the machine up and running do the following:

    git clone https://github.com/carlwilson/fmt-sniff.git
    cd fmt-sniff
    vagrant up
    vagrant ssh -c /vagrant/scripts/run.sh
The open your browser and navigate to http://localhost:8080

#### Local virtual env setup
First set up a local virtual environment, this example assumes you'll do this in the project root directory on a linux box or Mac:

    virtualenv -p python3 venv
    source venv/bin/activate
Next set the environment variable for the Flask web app:

    export FLASK_APP='corptest'
    export JISC_FFA_CONF_FILE='<pathtoproject>/conf/example.conf'
**NOTE** *these will need to be set for every new session for now*.

Finally install and run the  Flask application:

    pip install -e .
    flask run --port=8080
    The open your browser and navigate to http://localhost:8080

#### Debian flavoured distro
For now best to examine the [setup file](./scripts/setup.sh) and decide how you
want to configure it. Most of the tasks will be OK but you may want to setup the
virtualenv differently.

### Configuration
#### Amazon S3 credentials
If you want to use an S3 Bucket you'll need to set up the region and credentials
for the bucket you want to use.

##### S3 credentials file
Credentials are accessed using the credentials
files supported by the [official S3 CLI](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html). This can be set up manually by adding the following directories and files below your home directory:

**~/.aws/credentials**

    [default]
    aws_access_key_id=AKIAIOSFODNN7EXAMPLE
    aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

**~/.aws/config**

    [default]
    region=eu-west-2

##### S3 credentials environment variables
Alternatively you can export them as environment variables, on a linux box:

  export AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'
  export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  export AWS_DEFAULT_REGION='region=eu-west-2'

#### Amazon Bucket and data cache
The bucket endpoint is currently set in an [application constants file](https://github.com/carlwilson/fmt-sniff/blob/feat-configurable-tool-setup/corptest/const.py). The location of the data cache is set in the [same file](https://github.com/carlwilson/fmt-sniff/blob/feat-configurable-tool-setup/corptest/const.py).

Development
-----------
### Python development utilities
These are useful for ensuring your code follows best practise and establishing whether it's tested.

 - pylint for static source code checking
 - pep8 for complimentary similar
 - pytest for running unit tests
 - pytest-cov for generating test coverage reports

#### Running tests

You can run unit tests by:

    pytest ./tests/
and generate test coverage figures by:

    pytest --cov=corptest ./tests/
If you want to see which parts of your code aren't tested then:

     pytest --cov=corptest --cov-report=html ./tests/
After this you can open the file [`<projectRoot>/htmlcov/index.html`](./htmlcov/index.html) in your browser and survey the gory details.

### Tips
#### setup.py doesn't install....
These are all issues I encountered when developing this as a Python noob. All commands are Linux and if not stated they are run from the project root.
 - This is can be caused by caching of old compiled files. You can use this `find ./corptest -name '*.pyc' -delete` to remove all the compiled files below the current directory.
 - The build directory is out of synch, delete it: `rm -rf ./build`.
