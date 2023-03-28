#!/bin/bash

OPENAPI_FILE="hathor/cli/openapi_files/openapi_base.json"
SRC_FILE="hathor/version.py"
PACKAGE_FILE="pyproject.toml"
BUILD_VERSION_FILE="BUILD_VERSION"

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

if [[ -f "$BUILD_VERSION_FILE" ]]; then
	# Get the build version and ignore the suffix
    BUILD_VERSION=$(cat "$BUILD_VERSION_FILE" | cut -d"-" -f1)

	if [[ x${PACKAGE_VERSION}x != x${BUILD_VERSION}x ]]; then
		echo "Version different in ${PACKAGE_FILE} and ${BUILD_VERSION_FILE}"
		EXITCODE=-1
	fi
fi

exit $EXITCODE
