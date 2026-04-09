Docker
======

Run a full node in a Docker container.


Build an image
--------------
First, run `cp envvars.sample envvars` and change it according to your directories.

Then, just run `./build_image`.

The image name will be printed at the end of the build. For instance, "Successfully tagged hathor:v0.8.0-beta-26-g82ce1bd". The tag is gotten from `git describe` of the hathor-python repository.


Run a container
---------------
Run `docker run -p 10000:80 -ti hathor:<TAG> <PARAMS>`. Then, access `http://localhost:10000` in your browser.

If you would like to connected to the testnet, you must pass the `--testnet` parameter.

You can see the default parameters in the `run.sh` file.


Debug an image
--------------
Run `docker run --entrypoint /bin/bash -ti hathor:<TAG>`. Then, it will give access to a bash inside the container.

To get a bash in a running container, run `docker container exec -ti <CONTAINER_ID> /bin/bash`.


Useful commands
---------------

- List docker images: `docker image ls`
- List containers: `docker container ls`
- Clean stopped containers: `docker container prune`
- Clear dangling images: `docker image prune`
