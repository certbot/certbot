Certbot-Docker project
======================

Goal
----

This project is used to publish on DockerHub a new version of the official Certbot Docker, and related Certbot DNS plugins Dockers, upon release of a new version of Certbot.
It leverages the AutoBuild features of DockerHub to coordinate this publication through a continous integration/deployment approach.

High-level behavior
-------------------

When a new version tag (eg. v0.35.0) is pushed to this repository, it triggers a new build in each DockerHub project, to construct and publish the new version of the Docker,
containing the Certbot version corresponding to the pushed tag. With the example of the v0.35.0, the DockerHub projects will contain after few minutes a new tag v0.35.0,
whose the Docker contains Certbot v0.35.0.

Configuration
-------------

To setup the publication process, the target DockerHub project must be configured appropriately. There are two types of DockerHub projects to take into account:
* the Docker project for Certbot core features (eg. certbot/certbot)
* a Docker project for Certbot DNS plugins (eg. certbot/dns-rfc2136)

1) Define a GitHub user with push rights to the current GIT repository.
2) Create the DockerHub project if necessary.
3) Activate the AutoBuild feature, using the current GIT repository as source (eg. https://github.com/certbot-docker/certbot-docker.git) and the user defined in 1).
4) Define a unique tag build rule in AutoBuild configuration:

    _For a Certbot core Docker_ -> Source: `/^(v[0-9.]+).*$/`, Tag: `{\1}`, Dockerfile: `Dockerfile`, Build context: `/core`

    _For a Certbot DNS plugin Docker_ -> Source: `/^(v[0-9.]+).*$/`, Tag: `{\1}`, Dockerfile: `Dockerfile`, Build context: `/plugin`

Publication worfklow
--------------------

Assuming the version to publish is `v0.35.0`

1) Clone this repository locally, checkout branch `master` and ensure to have a clean workspace.
2) (Optional) Execute `./build.sh v0.35.0` to test the Dockers builds.
3) Execute `./deploy.sh v0.35.0` to trigger the publication of all Dockers with `v0.35.0` version.

Scripts usage
-------------

```
./build.sh [VERSION]
```

This script will build locally all Dockers for the given version using the same runtime than DockerHub.
This can be used to test the build process before invoking the actual publication workflow.

```
./deploy [VERSION]
```

This script will trigger the publication on DockerHub of all Dockers for the given version. To do so, this script:
- update the relevant `README.md` files that will be used as description in the DockerHub repositories,
- commit locally the modifications,
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
