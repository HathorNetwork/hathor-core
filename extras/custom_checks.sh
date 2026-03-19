#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Source dirs
SOURCE_DIRS=(hathor hathor_tests)

# Define your custom linter check functions here
# Each function should return 0 if everything is OK, and 1 if something is wrong.

function check_version_match() {
    # This function will check all source files containing the project version and return 1 in case
    # they don't match. When a version is provided as an environment variable, it is checked against the package version.

    OPENAPI_FILE="hathor/_openapi/openapi_base.json"
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
        EXITCODE=1
    fi

    if [[ x${PACKAGE_VERSION}x != x${OPENAPI_VERSION}x ]]; then
        echo "Version different in ${PACKAGE_FILE} and ${OPENAPI_FILE}"
        EXITCODE=1
    fi

    # We expect an optional environment variable containing a version string to be checked against the others
    if [[ -n ${VERSION} ]]; then
        if [[ x${PACKAGE_VERSION}x != x${VERSION}x ]]; then
            echo "Version different in ${PACKAGE_FILE} and VERSION environment variable"
            EXITCODE=1
        fi
    fi

    return $EXITCODE
}

function check_deprecated_typing() {
    local args=(
        check hathor hathor_tests
        --select TID251
        --config "lint.flake8-tidy-imports.banned-api = {'typing.List' = {msg = 'use builtin list instead'}, 'typing.Tuple' = {msg = 'use builtin tuple instead'}, 'typing.Dict' = {msg = 'use builtin dict instead'}, 'typing.Set' = {msg = 'use builtin set instead'}, 'typing.FrozenSet' = {msg = 'use builtin frozenset instead'}, 'typing.AbstractSet' = {msg = 'use builtin set or collections.abc.Set as appropriate instead'}, 'typing.DefaultDict' = {msg = 'use collections.defaultdict or builtin dict instead'}, 'typing.OrderedDict' = {msg = 'use collections.OrderedDict or builtin dict instead'}}"
    )
    ruff -q "${args[@]}"
}

function check_do_not_use_builtin_random_in_tests() {
    local args=(
        check hathor hathor_tests
        --select TID251
        --config "lint.flake8-tidy-imports.banned-api = {'random' = {msg = 'use self.rng or hathor.util.Random instead of random'}}"
        --config "lint.per-file-ignores = {'hathor/client.py' = ['TID251'], 'hathor/merged_mining/debug_api.py' = ['TID251'], 'hathor/util.py' = ['TID251'], 'hathor_tests/test_utils/test_leb128.py' = ['TID251']}"
    )
    ruff -q "${args[@]}"
}

function check_do_not_import_tests_in_hathor() {
    local args=(
        check hathor
        --select TID251
        --config "lint.flake8-tidy-imports.banned-api = {'hathor_tests' = {msg = 'do not import test definitions in the hathor module'}}"
    )
    ruff -q "${args[@]}"
}

function check_do_not_import_from_hathor_in_entrypoints() {
    local args=(
        check hathor_cli
        --select TID253
        --config "lint.flake8-tidy-imports.banned-module-level-imports = ['hathor']"
        --config "lint.per-file-ignores = {'hathor_cli/builder.py' = ['TID253'], 'hathor_cli/generate_genesis.py' = ['TID253'], 'hathor_cli/run_node_args.py' = ['TID253'], 'hathor_cli/events_simulator/event_forwarding_websocket_factory.py' = ['TID253'], 'hathor_cli/events_simulator/event_forwarding_websocket_protocol.py' = ['TID253']}"
    )
    ruff -q "${args[@]}"
}

function check_do_not_import_twisted_reactor_directly() {
    local args=(
        check hathor
        --select TID251
        --config "lint.flake8-tidy-imports.banned-api = {'twisted.internet.reactor' = {msg = 'use hathor.reactor.get_global_reactor() instead'}}"
        --config "lint.per-file-ignores = {'hathor/reactor/reactor.py' = ['TID251']}"
    )
    ruff -q "${args[@]}"
}

function check_do_not_compare_enums_with_is() {
    PATTERN=' is [a-zA-Z_]\w*\.[a-zA-Z_]\w*'

    if grep -REIn "$PATTERN" "${SOURCE_DIRS[@]}" | grep -v '# allow-is'; then
        echo 'do not use `is` for comparing with enums, use `==` instead'
        return 1
    fi
    return 0
}

# List of functions to be executed
checks=(
	check_version_match
	check_deprecated_typing
	check_do_not_use_builtin_random_in_tests
	check_do_not_import_tests_in_hathor
	check_do_not_import_from_hathor_in_entrypoints
	check_do_not_import_twisted_reactor_directly
	check_do_not_compare_enums_with_is
)

function run_check() {
    local check_name="$1"
    shift

    "$@"
    local result=$?
    if [ $result -ne 0 ]; then
        echo -e "${RED}Check ${check_name} FAILED${NC}"
        any_check_failed=1
    else
        echo -e "${GREEN}Check ${check_name} PASSED${NC}"
    fi
}

selected_checks=()
if [ $# -gt 0 ]; then
    selected_checks=("$@")
else
    selected_checks=("${checks[@]}")
fi

# Initialize a variable to track if any check fails
any_check_failed=0

# Loop over all checks
for check in "${selected_checks[@]}"; do
	run_check "$check" "$check"
done

# Exit with code 0 if no check failed, otherwise exit with code 1
if [ $any_check_failed -eq 0 ]; then
	echo -e "${GREEN}All checks PASSED${NC}"
	exit 0
else
	echo -e "${RED}Some checks FAILED${NC}"
	exit 1
fi
