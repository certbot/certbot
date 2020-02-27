Running Certbot in Docker 
=========================

Docker is an amazingly simple and quick way to obtain a certificate. However, this mode of operation is unable to install certificates or configure your webserver, because our installer plugins cannot reach your webserver from inside the Docker container.
 
**Most users should install Certbot by following the installation instructions at https://certbot.eff.org/instructions. You should only use Docker if you are sure you know what you are doing and have a good reason to do so.**

For more information, please read [Certbot - Running with Docker](https://certbot.eff.org/docs/install.html#running-with-docker).

Certbot-Docker project
======================

Goal
----

This project is used to publish a new version of the official Certbot Docker and related Certbot DNS plugins Dockers on DockerHub upon release of a new version of Certbot.
It leverages the AutoBuild features of DockerHub to coordinate this publication through a continous integration/deployment approach.

High-level behavior
-------------------

When a new version tag (eg. v0.35.0) is pushed to this repository, it triggers a new build in each DockerHub project, to construct and publish the new version of the Docker
containing the Certbot version corresponding to the pushed tag. For example, after following the instructions for v0.35.0 below, after a few minutes the DockerHub projects will contain a new tag "v0.35.0",
whose Docker contains Certbot v0.35.0.

Configuration
-------------

To set up the publication process, the target DockerHub project must be configured appropriately. There are two types of DockerHub projects to take into account:
* the Docker project for Certbot core features (eg. certbot/certbot)
* a Docker project for Certbot DNS plugins (eg. certbot/dns-rfc2136)

1) Define a GitHub user with push rights to the current GIT repository.
2) Create the DockerHub project if necessary.
3) Activate the AutoBuild feature, using the current GIT repository as source (eg. https://github.com/certbot-docker/certbot-docker.git) and the user defined in 1).
4) Define a unique tag build rule in AutoBuild configuration:

    _For a Certbot core Docker_ -> Source: `/^(v[0-9.]+).*$/`, Tag: `{\1}`, Dockerfile: `Dockerfile`, Build context: `/core`

    _For a Certbot DNS plugin Docker_ -> Source: `/^(v[0-9.]+).*$/`, Tag: `{\1}`, Dockerfile: `Dockerfile`, Build context: `/plugin`

Publication worfklow
-------------------

Assuming the version to publish is `v0.35.0`

1) Clone this repository locally, check out branch `master`, and ensure the workspace is clean.
2) (Optional) Execute `./build.sh v0.35.0` to test the Docker builds.
3) Execute `./deploy.sh v0.35.0` to trigger the publication of all Dockers with version `v0.35.0`.

Scripts usage
-------------

```
./build.sh [VERSION]
```

This script will locally build all Dockers for the given version using the same runtime as DockerHub.
This can be used to test the build process before invoking the actual publication workflow.

```
./deploy [VERSION]
```

This script will trigger the publication of all Dockers for the given version to DockerHub. To do so, this script will:
- update the relevant `README.md` files that will be used as descriptions in the DockerHub repositories,
- locally commit the modifications,
- tag this commit with the given version,
- push this tag and the updated `master` branch.

Assuming the version to publish is `v0.35.0`, the following docker images will be created at DockerHub.

- certbot/certbot:v0.35.0 *(amd64 architecture)*
- certbot/certbot:amd64-v0.35.0
- certbot/certbot:arm32v6-v0.35.0
- certbot/certbot:arm64v8-v0.35.0
- certbot/certbot:latest *(amd64 architecture)*
- certbot/certbot:amd64-latest
- certbot/certbot:arm32v6-latest
- certbot/certbot:arm64v8-latest
