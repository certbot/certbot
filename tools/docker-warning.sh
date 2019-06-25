#!/bin/sh -e
echo 'Warning: This Docker image is no longer receiving updates!' >&2
echo 'You should switch to the Docker images on Docker Hub at:' >&2
echo 'https://hub.docker.com/u/certbot' >&2
exec /opt/certbot/venv/bin/certbot $@
