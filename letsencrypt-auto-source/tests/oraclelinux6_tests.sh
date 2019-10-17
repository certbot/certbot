#!/bin/bash
# Start by making sure your system is up-to-date:
yum update -y >/dev/null

LE_AUTO_PY_34="certbot/letsencrypt-auto-source/letsencrypt-auto_py_34"
LE_AUTO="certbot/letsencrypt-auto-source/letsencrypt-auto"

# Last version of certbot-auto that was bootstraping Python 3.4 for CentOS 6 users
INITIAL_CERTBOT_VERSION_PY34="certbot 0.38.0"

# Check bootstrap from current letsencrypt-auto will fail, because SCL is not enabled.
if ! "$LE_AUTO" 2>&1 | grep -q "Enable the SCL repository and try running Certbot again."; then
  echo "ERROR: bootstrap was not aborted although SCL was not installed!"
  exit 1
fi

echo "PASSED: bootstrap was aborted since SCL was not installed."

# Bootstrap from the old letsencrypt-auto, Python 3.4 will be installed from EPEL.
"$LE_AUTO_PY_34" --no-self-upgrade -n >/dev/null 2>/dev/null

# Ensure Python 3.4 is installed
python3.4 --version >/dev/null 2>/dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: old letsencrypt-auto failed to install Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."
  exit 1
fi

echo "PASSED: bootstrap from old letsencrypt-auto succeeded and installed Python 3.4"

# Expect letsencrypt-auto to just fail to rebootstrap and start certbot in interactive
# shell since SCL is not installed.
if ! "$LE_AUTO" --version 2>&1 | grep -q "Enable the SCL repository and try running Certbot again."; then
  echo "FAILED: Script letsencrypt-auto managed to start Certbot in interactive shell while SCL is not enabled!"
  exit 1
fi

echo "PASSED: Script letsencrypt-auto did not rebootstrap and did not star Certbot."

# Expect letsencrypt-auto to not update certbot, but start it anyway in non-interactive
# shell since SCL is not installed.
# NB: Readline has an issue on all Python versions for CentOS 6, making `certbot --version`
# output an unprintable ASCII character on a new line at the end.
# So we take the second last line of the output.
version=$($LE_AUTO --version 2>/dev/null | tail -2 | head -1)

if [ -z "$version" ]; then
  echo "ERROR: Script letsencrypt-auto failed to start certbot in a non-interactive shell while SCL was not enabled."
  exit 1
fi

if [ "$version" != "$INITIAL_CERTBOT_VERSION_PY34" ]; then
  echo "ERROR: Script letsencrypt-auto upgraded certbot in a non-interactive shell while SCL was not enabled."
  exit 1
fi

echo "PASSED: Script letsencrypt-auto did not upgrade certbot but started it successfully while SCL was not enabled."

# Enable SCL
yum install -y oracle-softwarecollection-release-el6 >/dev/null

# Following test is exectued in a subshell, to not leak any environment variable
(
  export VENV_PATH=$(mktemp -d)

  # Expect letsencrypt-auto to bootstrap successfully since SCL is available
  "$LE_AUTO" -n >/dev/null 2>/dev/null

  if [ "$($VENV_PATH/bin/python -V 2>&1 | cut -d" " -f2 | cut -d. -f1-2)" != "3.6" ]; then
    echo "ERROR: Script letsencrypt-auto failed to bootstrap and install Python 3.6 while SCL is available."
    exit 1
  fi

  if ! $VENV_PATH/bin/certbot --version > /dev/null 2> /dev/null; then
    echo "ERROR: Script letsencrypt-auto did not install certbot correctly while SCL is enabled."
    exit 1
  fi
)

echo "PASSED: Script letsencrypt-auto correctly bootstraped Certbot using rh-python36 when SCL is available."
