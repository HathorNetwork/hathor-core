#!/bin/bash

BASENAME=`basename $0`

if [ $# -ne 3 ]; then
	echo "usage: ${BASENAME} <install_dir> <node_host> <deploy_token>"
	exit 1
fi

export INSTALL_DIR=$1
export NODE_HOST=$2
DEPLOY_TOKEN=$3

BASEDIR=`pwd`

cd ${INSTALL_DIR}

git clone https://${DEPLOY_TOKEN}@gitlab.com/HathorNetwork/admin-frontend.git || exit 1

sed -i -e 's#http://localhost:8080/#/api/#g' -e 's#ws://127.0.0.1:8080/ws/#wss://'${NODE_HOST}'/api/ws/#g' admin-frontend/src/constants.js

sudo add-apt-repository -y ppa:certbot/certbot
sudo apt update
curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
sudo apt install -y nginx nodejs certbot

sudo certbot certonly --agree-tos -m hathor@hathor.network --standalone --preferred-challenges http -d ${NODE_HOST} --pre-hook "/etc/init.d/nginx stop" --post-hook "/etc/init.d/nginx start"

envsubst < ${BASEDIR}/nginx.conf.template > nginx.conf
sudo ln -s ${INSTALL_DIR}/nginx.conf /etc/nginx/sites-enabled/${NODE_HOST}
touch htpasswd
sudo /etc/init.d/nginx reload

cd admin-frontend/
npm install
npm run-script build

