# Debugging

## Purpose

Here are some useful tips and tools for debugging.

## Profiling

You can enable and disable profiling using the HTTP API, so you must use `--status 8080`.

### Start profiler

    curl --data '{"start": true}' "http://127.0.0.1:8080/v1a/profiler/"

### Stop profiler

    curl --data '{"stop": true, "filepath": "/full/path/to/output.prof"}' "http://127.0.0.1:8080/v1a/profiler/"

## Tools

### pudb

You can use `--pudb` to enable pudb to stop execution when an unhandled exception is raised.

Notice that you have to manually install the package `pudb`.

Documentation: https://documen.tician.de/pudb/


### objgraph

You can use `objgraph` to draw object reference graphs using graphviz. For example, you can use
`objgraph.show_backrefs(x)` to find out why an object has not been cleared by the garbage collector.

Notice that you have to manually install `objgraph`.

Documentation: https://mg.pov.lt/objgraph/
