#!/bin/sh -e
# pip installs packages in editable mode using certbot-auto's requirements file
# as constraints

args=""
for requirement in "$@" ; do
  args="$args -e $requirement"
done

"$(dirname $0)/pip_install.sh" $args
