#!/bin/sh -e
#
# Installs and updates letencrypt virtualenv
#
# USAGE: source ./dev/venv.sh


XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
VENV_NAME="letsencrypt"
VENV_PATH=${VENV_PATH:-"$XDG_DATA_HOME/$VENV_NAME"}

# virtualenv call is not idempotent: it overwrites pip upgraded in
# later steps, causing "ImportError: cannot import name unpack_url"
if [ ! -d $VENV_PATH ]
then
  virtualenv --no-site-packages --python python2 $VENV_PATH
fi

. $VENV_PATH/bin/activate
pip install -U setuptools
pip install -U pip

pip install -U letsencrypt letsencrypt-apache # letsencrypt-nginx

echo
echo "Congratulations, Let's Encrypt has been successfully installed/updated!"
echo
printf "%s" "Your prompt should now be prepended with ($VENV_NAME). Next "
printf "time, if the prompt is different, 'source' this script again "
printf "before running 'letsencrypt'."
echo
echo
echo "You can now run 'letsencrypt --help'."
