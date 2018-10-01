#!/bin/bash

BASENAME=`basename $0`

if [ $# -ne 3 ]; then
	echo "usage: ${BASENAME} <install_dir> <node_host> <deploy_token>"
	exit 1
fi

INSTALL_DIR=$1
NODE_HOST=$2
DEPLOY_TOKEN=$3

./install_node.sh "${INSTALL_DIR}" "${NODE_HOST}" "${DEPLOY_TOKEN}"
./install_admin.sh "${INSTALL_DIR}" "${NODE_HOST}" "${DEPLOY_TOKEN}"
