#!/bin/bash

###
# This script will check all source files containing the project version and exit with an error code -1 in case
# they don't match.
#
# usage: ./extras/check_version.sh [version]
#
# example: ./extras/check_version.sh 0.52.1
#
# When a version is provided, it is checked against the package version.
###

OPENAPI_FILE="hathor/cli/openapi_files/openapi_base.json"
SRC_FILE="hathor/version.py"
PACKAGE_FILE="pyproject.toml"

OPENAPI_VERSION=`grep "version\":" ${OPENAPI_FILE} | cut -d'"' -f4`
SRC_VERSION=`grep "BASE_VERSION =" ${SRC_FILE} | cut -d "'" -f2`
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

# We expect an optional argument containing a version string to be checked against the others
if [[ $# -eq 1 ]]; then
    if [[ x${PACKAGE_VERSION}x != x$1x ]]; then
        echo "Version different in ${PACKAGE_FILE} and passed argument"
        EXITCODE=-1
    fi
fi

exit $EXITCODE
