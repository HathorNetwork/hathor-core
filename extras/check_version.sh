#!/bin/bash

OPENAPI_FILE="hathor/cli/openapi_files/openapi_base.json"
SRC_FILE="hathor/version.py"
PACKAGE_FILE="pyproject.toml"

OPENAPI_VERSION=`grep "version\":" ${OPENAPI_FILE} | cut -d'"' -f4`
SRC_VERSION=`grep "__version__" ${SRC_FILE} | cut -d "'" -f2`
PACKAGE_VERSION=`grep '^version' ${PACKAGE_FILE} | cut -d '"' -f2`

# For debugging:
# echo x${SRC_VERSION}x
# echo x${OPENAPI_VERSION}x
# echo x${PACKAGE_VERSION}x

EXITCODE=0

if [[ x${PACKAGE_VERSION}x != x${SRC_VERSION}x ]]; then
	echo "Version different in ${PACKAGE_FILE} and ${SRC_FILE}"
	EXITCODE=-1
fi

if [[ x${PACKAGE_VERSION}x != x${OPENAPI_VERSION}x ]]; then
	echo "Version different in ${PACKAGE_FILE} and ${OPENAPI_FILE}"
	EXITCODE=-1
fi

exit $EXITCODE
