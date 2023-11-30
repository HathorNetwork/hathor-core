#!/bin/sh
if [ "$1" = "--memray-live" ]; then
    shift
    exec memray run --native --trace-python-allocators --live-remote -p 7777 -q -m hathor "$@"
elif [ "$1" = "--memray-output" ]; then
    shift
    exec memray run --native --trace-python-allocators --output=/mnt/memray.bin -q -m hathor "$@"
else
    exec python -m hathor "$@"
fi
