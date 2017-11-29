#!/bin/sh -ex
# pip installs the requested packages in editable mode and runs unit tests on
# them. Each package is installed and tested in the order they are provided
# before the script moves on to the next package. If CERTBOT_NO_PIN is set not
# set to 1, packages are installed using certbot-auto's requirements file as
# constraints.

python -c 'from __future__ import print_function; import pip; import setuptools; import wheel; print(pip.__version__); print(setuptools.__version__); print(wheel.__version__)'

if [ "$CERTBOT_NO_PIN" = 1 ]; then
  pip_install="pip install -e"
else
  pip_install="$(dirname $0)/pip_install_editable.sh"
fi

for requirement in "$@" ; do
  $pip_install $requirement
  pkg=$(echo $requirement | cut -f1 -d\[)  # remove any extras such as [dev]
  if [ $pkg = "." ]; then
    pkg="certbot"
  fi
  nosetests -v $pkg --processes=-1 --process-timeout=100
done
