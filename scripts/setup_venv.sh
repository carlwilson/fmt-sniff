#!/usr/bin/env bash
mkdir -p ~/.venvs
virtualenv ~/.venvs/fmt-sniff
source ~/.venvs/fmt-sniff/bin/activate
pip install -e /vagrant
deactivate
