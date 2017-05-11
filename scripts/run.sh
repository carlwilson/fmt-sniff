#!/usr/bin/env bash
source ~/.venvs/fmt-sniff/bin/activate
export FLASK_APP='corptest'
# export JISC_FFA_CONF_FILE='/vagrant/conf/example.conf'
export JISC_FFA_CONF_PROFILE='vagrant'
cd /vagrant
flask run --port=8080 --host=0.0.0.0
