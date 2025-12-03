# Developing

## Purpose

Miscellany of relevant commands for developing Hathor core.

## Tests

Check if code seems alright:

```
make check
```

Test and coverage:

```
make tests
```

## Generate documentation

Generate Sphinx docs:

```
cd docs
make html
make latexpdf
```

The output will be written to `docs/_build/html/`.


Generate API docs:

```
hathor-cli generate_openapi_json
redoc-cli bundle hathor/_openapi/openapi.json --output index.html
```

[open-issue]: https://github.com/HathorNetwork/hathor-core/issues/new
[create-pr]: https://github.com/HathorNetwork/hathor-core/compare
