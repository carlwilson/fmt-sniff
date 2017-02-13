Research Data Format Identification
===================================
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
- Python
- Any linux distro although the provided [install script](./scripts/setup.sh) is debian flavour specific as it uses `apt`.

### Dependencies
The setup script uses `apt` to install the following packages:
  - `unzip` to unpack the DROID download;
  - `openjdk-7-jre` for running DROID and Tika;
  - `python-dev` for compiling / installing Python dependencies;
  - `libxml2-dev` for Python XML support;
  - `libxslt1-dev` for Python XSLT support;
  - `zlib1g-dev` C libraries and headers for Python C libraries;
  - `python3-dev` development headers for Python 3; and
  - `virtualenv` for isolated Python development environment.

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

#### Debian flavoured distro
For now best to examine the [setup file](./scripts/setup.sh) and decide how you
want to configure it. Most of the tasks will be OK but you may want to setup the
virtualenv differently.

### Configuration
#### Amazon S3 credentials
If you want to use an S3 Bucket you'll need to set up the region and credentials
for the bucket you want to use. Credentials are accessed using the credentials
files supported by the [official S3 CLI](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html). This can be set up manually by adding the following directories and files below your home directory:

**~/.aws/credentials**

    [default]
    aws_access_key_id=AKIAIOSFODNN7EXAMPLE
    aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

**~/.aws/config**

    [default]
    region=eu-west-2

#### Amazon Bucket and data cache
The bucket endpoint is currently set in an [application constants file](https://github.com/carlwilson/fmt-sniff/blob/feat-configurable-tool-setup/corptest/const.py#L18). The location of the data cache is set in the [same file](https://github.com/carlwilson/fmt-sniff/blob/feat-configurable-tool-setup/corptest/const.py#L17).
