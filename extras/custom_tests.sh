#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TESTS_DIR="extras/custom_tests"

# List of test scripts to be executed
tests=(
	/side_dag/test_one_fails.py
	/side_dag/test_both_fail.py
)

# Initialize a variable to track if any test fails
any_test_failed=0

# Loop over all tests
for test in "${tests[@]}"; do
  echo -e "${BLUE}Testing $test${NC}"
	PYTHONPATH=$TESTS_DIR python $TESTS_DIR/$test
  result=$?
	if [ $result -ne 0 ]; then
		echo -e "${RED}Test $test FAILED${NC}"
		any_test_failed=1
	else
		echo -e "${GREEN}Test $test PASSED${NC}"
	fi
done

# Exit with code 0 if no test failed, otherwise exit with code 1
if [ $any_test_failed -eq 0 ]; then
	echo -e "${GREEN}All tests PASSED${NC}"
	exit 0
else
	echo -e "${RED}Some tests FAILED${NC}"
	exit 1
fi
