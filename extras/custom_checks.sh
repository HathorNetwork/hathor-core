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

function check_do_not_use_builtin_random_in_tests() {
	# If the check fails, return 1
	# If the check passes, return 0
	exclude=(
		hathor/merged_mining/debug_api.py
		hathor/client.py
		hathor_cli/tx_generator.py
		hathor_tests/test_utils/test_leb128.py
	)
	exclude_params=()
	for item in "${exclude[@]}"; do
		exclude_params+=(-not -path "*$item*")
	done
	if find "${SOURCE_DIRS[@]}" "${exclude_params[@]}" -type f -print0 | xargs -0 grep -l '\<import .*\<random\>'; then
		echo '"import random" found in the files above'
		echo 'use `self.rng` or `hathor.util.Random` instead of `random`'
		return 1
	fi
	return 0
}

function check_deprecated_typing() {
	if grep -RIn '\<typing .*\<import .*\<\(Tuple\|List\|Dict\|Set\|FrozenSet\|AbstractSet\|DefaultDict\|OrderedDict\)\>' "${SOURCE_DIRS[@]}"; then
		echo 'do not use typing.List/Tuple/Dict/... for type annotations use builtin list/tuple/dict/... instead'
		echo 'for more info check the PEP 585 doc: https://peps.python.org/pep-0585/'
		return 1
	fi
	return 0
}

function check_do_not_import_tests_in_hathor() {
	if grep -Rn '\<.*import .*hathor_tests.*\>\|\<.*from .*hathor_tests.* import\>' "hathor" | grep -v '# skip-import-tests-custom-check'; then
		echo 'do not import test definitions in the hathor module'
		echo 'move them from hathor_tests to hathor instead'
		echo 'alternatively, comment `# skip-import-tests-custom-check` to exclude a line.'
		return 1
	fi
	return 0
}

function check_do_not_import_from_hathor_in_entrypoints() {
    EXCLUDES=(--exclude=builder.py)
    PATTERN='^import .*hathor.*\|^from .*hathor.* import'

    if grep -Rn $EXCLUDES "$PATTERN" "hathor_cli" | grep -v 'from hathor_cli.run_node import RunNode' | grep -v '# skip-cli-import-custom-check'; then
        echo 'do not import from `hathor` in the module-level of a CLI entrypoint.'
        echo 'instead, import locally inside the function that uses the import.'
        echo 'alternatively, comment `# skip-cli-import-custom-check` to exclude a line.'
        return 1
    fi
    return 0
}

function check_do_not_import_twisted_reactor_directly() {
    EXCLUDES="--exclude=reactor.py --exclude=conftest.py"
    PATTERN='\<.*from .*twisted.internet import .*reactor\>'

    if grep -Rn $EXCLUDES "$PATTERN" "${SOURCE_DIRS[@]}"; then
        echo 'do not use `from twisted.internet import reactor` directly.'
        echo 'instead, use `hathor.reactor.get_global_reactor()`.'
        return 1
    fi
    return 0
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
	check_do_not_use_builtin_random_in_tests
	check_deprecated_typing
	check_do_not_import_tests_in_hathor
	check_do_not_import_from_hathor_in_entrypoints
	check_do_not_import_twisted_reactor_directly
	check_do_not_compare_enums_with_is
)

# Initialize a variable to track if any check fails
any_check_failed=0

# Loop over all checks
for check in "${checks[@]}"; do
	$check
	result=$?
	if [ $result -ne 0 ]; then
		echo -e "${RED}Check $check FAILED${NC}"
		any_check_failed=1
	else
		echo -e "${GREEN}Check $check PASSED${NC}"
	fi
done

# Exit with code 0 if no check failed, otherwise exit with code 1
if [ $any_check_failed -eq 0 ]; then
	echo -e "${GREEN}All checks PASSED${NC}"
	exit 0
else
	echo -e "${RED}Some checks FAILED${NC}"
	exit 1
fi
