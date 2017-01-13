#!/bin/sh -e

INIT_PATH=$(realpath $(dirname $0)"/../certbot/__init__.py")
grep "__version__" $INIT_PATH | cut -d\' -f2
