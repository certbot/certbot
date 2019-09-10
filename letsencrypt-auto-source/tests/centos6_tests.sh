#!/bin/bash
# Start by making sure your system is up-to-date:
yum update -y > /dev/null
yum install -y centos-release-scl > /dev/null
yum install -y python27 > /dev/null 2> /dev/null

LE_AUTO_PY_34="certbot/letsencrypt-auto-source/letsencrypt-auto_py_34"
LE_AUTO="certbot/letsencrypt-auto-source/letsencrypt-auto"

# we're going to modify env variables, so do this in a subshell
(
. scl_source enable python27

# ensure python 3 isn't installed
python3 --version > /dev/null 2> /dev/null
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo "ERROR: Python3 is already installed."
  exit 1
fi

# ensure python2.7 is available
python2.7 --version > /dev/null 2> /dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: Python2.7 is not available."
  exit 1
fi

# bootstrap, but don't install python 3.
"$LE_AUTO" --no-self-upgrade -n > /dev/null 2> /dev/null

# ensure python 3 isn't installed
python3 --version > /dev/null 2> /dev/null
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo "ERROR: letsencrypt-auto installed Python3 even though Python2.7 is present."
  exit 1
fi

echo "PASSED: Did not upgrade to Python3 when Python2.7 is present."
)

# ensure python2.7 isn't available
python2.7 --version > /dev/null 2> /dev/null
RESULT=$?
if [ $RESULT -eq 0 ]; then
  error "ERROR: Python2.7 is still available."
  exit 1
fi

# Skip self upgrade due to Python 3 not being available.
if ! "$LE_AUTO" 2>&1 | grep -q "WARNING: couldn't find Python"; then
  echo "ERROR: Python upgrade failure warning not printed!"
  exit 1
fi

# bootstrap from the old letsencrypt-auto, this time installing python3.4
"$LE_AUTO_PY_34" --no-self-upgrade -n > /dev/null 2> /dev/null

# ensure python 3.4 is installed
python3.4 --version > /dev/null 2> /dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: letsencrypt-auto failed to install Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."
  exit 1
fi

echo "PASSED: Successfully upgraded to Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."

# now bootstrap from current letsencrypt-auto, that will install python3.6 from SCL
"$LE_AUTO" --no-self-upgrade -n > /dev/null 2> /dev/null

# enable SCL rh-python36
. scl_source enable rh-python36

# ensure python 3.6 is installed
python3.6 --version > /dev/null 2> /dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: letsencrypt-auto failed to install Python3.6 using current letsencrypt-auto when only Python2.6/Python3.4 are present."
  exit 1
fi

echo "PASSED: Successfully upgraded to Python3.6 using curent letsencrypt-auto when only Python2.6/Python3.4 are present."

export VENV_PATH=$(mktemp -d)
"$LE_AUTO" -n --no-bootstrap --no-self-upgrade --version >/dev/null 2>&1
if [ "$($VENV_PATH/bin/python -V 2>&1 | cut -d" " -f2 | cut -d. -f1-2)" != "3.6" ]; then
  echo "ERROR: Python 3.6 wasn't used with --no-bootstrap!"
  exit 1
fi
unset VENV_PATH

# test using python3
pytest -v -s certbot/letsencrypt-auto-source/tests
