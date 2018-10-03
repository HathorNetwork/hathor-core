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

git clone https://${DEPLOY_TOKEN}@gitlab.com/HathorNetwork/hathor-python.git || exit 1

sudo apt update
sudo apt install -y python3 python3-dev python3-pip python3-venv build-essential graphviz libssl-dev
sudo apt install -y supervisor

envsubst < ${BASEDIR}/supervisor.conf.template > supervisor.conf
sudo ln -s ${INSTALL_DIR}/supervisor.conf /etc/supervisor/conf.d/hathord.conf
sudo /etc/init.d/supervisor restart

mkdir logs/
mkdir data/

cd hathor-python/
python3 -m venv --prompt "venv/hathor" venv
source ./venv/bin/activate
pip install wheel
pip install -r requirements.txt

python gen_peer_id.py >peer_id.json

envsubst < ${BASEDIR}/run_hathord.template > run_hathord
envsubst < ${BASEDIR}/run_miner.template > run_miner

chmod 744 run_hathord
chmod 744 run_miner
