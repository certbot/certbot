#!/bin/bash
set -e
# Start by making sure your system is up-to-date:
yum update -y > /dev/null
yum install -y centos-release-scl > /dev/null
yum install -y python27 > /dev/null 2> /dev/null

LE_AUTO="certbot/letsencrypt-auto-source/letsencrypt-auto"

echo ""

# we're going to modify env variables, so do this in a subshell
(
# ensure CentOS6 32bits is not supported anymore, and so certbot is not installed
export UNAME_FAKE_32BITS=true
if ! "$LE_AUTO" 2>&1 | grep -q "Certbot cannot be installed."; then
  echo "On CentOS 32 bits, certbot-auto installed certbot."
  exit 1
fi
)

echo "PASSED: On CentOS 6 32 bits, certbot-auto refused to install certbot."

# we're going to modify env variables, so do this in a subshell
(
source /opt/rh/python27/enable

# ensure python 3 isn't installed
if python3 --version 2> /dev/null; then
  echo "Python3 is already installed."
  exit 1
fi

# ensure python2.7 is available
python2.7 --version 2> /dev/null
RESULT=$?
if ! python2.7 --version 2> /dev/null; then
  echo "Python2.7 is not available."
  exit 1
fi

# bootstrap, but don't install python 3.
"$LE_AUTO" --no-self-upgrade -n --version > /dev/null 2> /dev/null

# ensure python 3 isn't installed
if python3 --version 2> /dev/null; then
  echo "letsencrypt-auto installed Python3 even though Python2.7 is present."
  exit 1
fi
)

echo "PASSED: Did not upgrade to Python3 when Python2.7 is present."

# ensure python2.7 isn't available
if python2.7 --version 2> /dev/null; then
  echo "Python2.7 is still available."
  exit 1
fi

# Skip self upgrade due to Python 3 not being available.
if ! "$LE_AUTO" 2>&1 | grep -q "WARNING: couldn't find Python"; then
  echo "Python upgrade failure warning not printed!"
  exit 1
fi

# bootstrap, this time installing python3
"$LE_AUTO" --no-self-upgrade -n --version > /dev/null 2> /dev/null

# ensure python 3 is installed
if ! python3 --version > /dev/null; then
  echo "letsencrypt-auto failed to install Python3 when only Python2.6 is present."
  exit 1
fi

echo "PASSED: Successfully upgraded to Python3 when only Python2.6 is present."
echo ""

export VENV_PATH=$(mktemp -d)
"$LE_AUTO" -n --no-bootstrap --no-self-upgrade --version >/dev/null 2>&1
if [ "$($VENV_PATH/bin/python -V 2>&1 | cut -d" " -f2 | cut -d. -f1)" != 3 ]; then
  echo "Python 3 wasn't used with --no-bootstrap!"
  exit 1
fi
unset VENV_PATH

# we're going to modify env variables, so do this in a subshell
(
# ensure CentOS6 32bits is not supported anymore, and so certbot
# is not upgraded nor reinstalled.
export UNAME_FAKE_32BITS=true
if ! "$LE_AUTO" --version > /dev/null 2> /dev/null; then
  echo "On CentOS 6 32 bits, certbot-auto failed to run installed certbot instance."
  exit 1
fi
if ! "$LE_AUTO" --version 2>&1 | grep -q "Certbot will no longer receive updates."; then
  echo "On CentOS 6 32 bits, certbot-auto upgraded installed certbot instance."
  exit 1
fi
if ! "$LE_AUTO" --install-only 2>&1 | grep -q "Certbot cannot be installed."; then
  echo "On CentOS 6 32 bits, certbot-auto installed certbot again."
  exit 1
fi
)

# we're going to modify env variables, so do this in a subshell
(
# Prepare a certbot installation in the old venv path
export VENV_PATH=~/.local/share/letsencrypt
"$LE_AUTO" --install-only > /dev/null 2> /dev/null
# fake 32 bits mode
export UNAME_FAKE_32BITS=true
if ! "$LE_AUTO" --version > /dev/null 2> /dev/null; then
  echo "On CentOS 6 32 bits, certbot-auto failed to run installed certbot instance in the old venv path."
  exit 1
fi
if ! "$LE_AUTO" 2>&1 | grep -q "Certbot will no longer receive updates."; then
  echo "On CentOS 6 32 bits, certbot-auto upgraded installed certbot in the old venv path."
  exit 1
fi
)

echo "PASSED: On CentOS 6 32 bits, certbot-auto refused to install/upgrade certbot."

# test using python3
pytest -v -s certbot/letsencrypt-auto-source/tests
