#!/bin/sh -e
# pip installs the requested packages in editable mode and runs unit tests on
# them. Each package is installed and tested in the order they are provided
# before the script moves on to the next package. If CERTBOT_NO_PIN is set not
# set to 1, packages are installed using pinned versions of all of our
# dependencies. See pip_install.sh for more information on the versions pinned
# to.

if [ "$CERTBOT_NO_PIN" = 1 ]; then
  pip_install="pip install -q -e"
else
  pip_install="$(dirname $0)/pip_install_editable.sh"
fi

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
  "$(dirname $0)/pytest.sh" --pyargs $pkg
done
