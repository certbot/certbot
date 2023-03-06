Running Certbot in Docker 
=========================

Docker is an amazingly simple and quick way to obtain a certificate. However, this mode of operation is unable to install certificates automatically or configure your webserver, because our installer plugins cannot reach your webserver from inside the Docker container.
 
**Most users should install Certbot by following the installation instructions at https://certbot.eff.org/instructions. You should only use Docker if you are sure you know what you are doing (you understand [volumes](https://docs.docker.com/storage/volumes/)) and have a good reason to do so, such as following the [one service per container rule](https://docs.docker.com/config/containers/multi-service_container/).**

For more information, please read [Certbot - Running with Docker](https://certbot.eff.org/docs/install.html#running-with-docker).


Certbot Docker Tools
======================

Goal
----

This code is used to build and deploy new versions of the Certbot and Certbot
DNS plugin Docker images to Docker Hub.

High-level behavior
-------------------

Running `./build.sh <TAG> all` causes the Docker images to be built for all 
supported architectures, where `<TAG>` is the base of the tag that should be 
given to the generated images. The tag should either be `nightly` or a git 
version tag like `v2.2.0`. For version tags above `v2.0.0`, additional tags 
for `latest` are also generated. The generated images are stored in a local 
cache backed by the local filesystem.

Running `./test.sh <TAG> all` either loads images from the filesystem cache
or generates said images on demand, loads them into the local docker cache,
and runs a test command to validate the image contents.

Running `./deploy.sh <TAG> all` will push the previously generated images 
to Docker Hub. The per-architecture images are accessible through the 
corresponding multi-arch manifest by using the `docker pull --platform
<platform spec> <IMAGE>:<TAG>` command.

Configuration
-------------

To run these scripts you need:

1. A computer with Docker installed and the Docker daemon running. You probably 
don't want to use the docker snap as these scripts have failed when using that 
in the past.
2. To be logged into Docker Hub with an account able to push to the Certbot and 
Certbot DNS Docker images on Docker Hub. Altering the value of `DOCKER_HUB_ORG` 
in `lib/common` will allow you to push to your own account for testing.
