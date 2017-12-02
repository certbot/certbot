#!/bin/sh -e
# pip installs the requested packages in editable mode and runs unit tests on
# them. Each package is installed and tested in the order they are provided
# before the script moves on to the next package.

pip_install="$(dirname $0)/pip_install_editable.sh"

set -x
for requirement in "$@" ; do
  $pip_install $requirement
  pkg=$(echo $requirement | cut -f1 -d\[)  # remove any extras such as [dev]
  if [ $pkg = "." ]; then
    pkg="certbot"
  else
    # Work around a bug in pytest/importlib for the deprecated Python 3.3.
    # See https://travis-ci.org/certbot/certbot/jobs/308774157#L1333.
    pkg=$(echo "$pkg" | tr - _)
  fi
  pytest --numprocesses auto --quiet --pyargs $pkg
done
