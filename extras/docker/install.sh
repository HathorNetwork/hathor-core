#!/bin/bash

BASEDIR=`pwd`

HTR_PATH_DATA="/var/lib/hathor"
HTR_PATH_HOME="/usr/share/hathor"
HTR_PATH_LOGS="/var/log/hathor"

# Create user, group, and directories.
addgroup --system hathor && \
useradd --system -g hathor -s /bin/bash hathor && \
mkdir -p "$HTR_PATH_DATA" "$HTR_PATH_HOME" "$HTR_PATH_LOGS" "${HTR_PATH_HOME}/webadmin" && \
chown -R hathor:hathor "$HTR_PATH_DATA" "$HTR_PATH_HOME" "$HTR_PATH_LOGS"

# Install hathor.
pip3 install --no-cache-dir /tmp/hathor.tar.gz
tar xvzf /tmp/hathor-webadmin.tar.gz -C "${HTR_PATH_HOME}/webadmin/"

ln -s ../sites-available/hathor-webadmin /etc/nginx/sites-enabled/hathor-webadmin
