Openapi Docs
============

Installing ReDoc cli
---------------------

Install via npm (https://github.com/Rebilly/ReDoc/blob/master/cli/README.md):

    npm install -g redoc-cli


Run a ReDoc server
----------------

Run the server choosing your openapi file and the port where it will run (--watch can be used to watch for changes in openapi file during development)

    redoc-cli serve openapi.json --port 8081


Adding new request to the docs
------------------------------

Each resources file has an attribute called openapi, which is a dict that will be used to create the json openapi file. All resource classes that must be added in api documentation page must have a decorator (register_resource). It's also important to make sure that all registered resource classes must be imported in get_registered_resources method.


Adding new component
--------------------

In case you need to add a new component to be used as a schema you need to edit the file `docs/api/openapi_components.json` and add the new schema.


Updating openapi json
---------------------

After adding new requests or components you need to generate a new openapi json, so your changes appear in the docs page. To do it just run

    ./hathor-cli generate_openapi_json