#!/bin/bash
set -e
# Start by making sure your system is up-to-date:
yum update -y >/dev/null
yum install -y centos-release-scl >/dev/null
yum install -y python27 >/dev/null 2>/dev/null

LE_AUTO_PY_34="certbot/letsencrypt-auto-source/letsencrypt-auto_py_34"
LE_AUTO="certbot/letsencrypt-auto-source/letsencrypt-auto"

# Last version of certbot-auto that was bootstraping Python 3.4 for CentOS 6 users
INITIAL_CERTBOT_VERSION_PY34="certbot 0.38.0"

# we're going to modify env variables, so do this in a subshell
(
# ensure CentOS6 32bits is not supported anymore, and so certbot is not installed
export UNAME_FAKE_32BITS=true
if ! "$LE_AUTO" 2>&1 | grep -q "Certbot cannot be installed."; then
  echo "ERROR: certbot-auto installed certbot on 32-bit CentOS."
  exit 1
fi
)

echo "PASSED: On CentOS 6 32 bits, certbot-auto refused to install certbot."

# we're going to modify env variables, so do this in a subshell
(
  . /opt/rh/python27/enable

  # ensure python 3 isn't installed
  if python3 --version 2> /dev/null; then
    echo "ERROR: Python3 is already installed."
    exit 1
  fi

  # ensure python2.7 is available
  if ! python2.7 --version 2> /dev/null; then
    echo "ERROR: Python2.7 is not available."
    exit 1
  fi

  # bootstrap, but don't install python 3.
  "$LE_AUTO" --no-self-upgrade -n --version > /dev/null 2> /dev/null

  # ensure python 3 isn't installed
  if python3 --version 2> /dev/null; then
    echo "ERROR: letsencrypt-auto installed Python3 even though Python2.7 is present."
    exit 1
  fi

  echo "PASSED: Did not upgrade to Python3 when Python2.7 is present."
)

# ensure python2.7 isn't available
if python2.7 --version 2> /dev/null; then
  echo "ERROR: Python2.7 is still available."
  exit 1
fi

# Skip self upgrade due to Python 3 not being available.
if ! "$LE_AUTO" 2>&1 | grep -q "WARNING: couldn't find Python"; then
  echo "ERROR: Python upgrade failure warning not printed!"
  exit 1
fi

# bootstrap from the old letsencrypt-auto, this time installing python3.4
"$LE_AUTO_PY_34" --no-self-upgrade -n --version >/dev/null 2>/dev/null

# ensure python 3.4 is installed
if ! python3.4 --version >/dev/null 2>/dev/null; then
  echo "ERROR: letsencrypt-auto failed to install Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."
  exit 1
fi

echo "PASSED: Successfully upgraded to Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."

# As "certbot-auto" (so without implicit --non-interactive flag set), check that the script
# refuses to install SCL Python 3.6 when run in a non interactive shell (simulated here
# using | tee /dev/null) if --non-interactive flag is not provided.
cp "$LE_AUTO" /tmp/certbot-auto
# NB: Readline has an issue on all Python versions for CentOS 6, making `certbot --version`
# output an unprintable ASCII character on a new line at the end.
# So we take the second last line of the output.
version=$(/tmp/certbot-auto --version 2>/dev/null | tee /dev/null | tail -2 | head -1)

if [ "$version" != "$INITIAL_CERTBOT_VERSION_PY34" ]; then
  echo "ERROR: certbot-auto upgraded certbot in a non-interactive shell with --non-interactive flag not set."
  exit 1
fi

echo "PASSED: certbot-auto did not upgrade certbot in a non-interactive shell with --non-interactive flag not set."

if [ -f /opt/rh/rh-python36/enable ]; then
  echo "ERROR: certbot-auto installed Python3.6 in a non-interactive shell with --non-interactive flag not set."
  exit 1
fi

echo "PASSED: certbot-auto did not install Python3.6 in a non-interactive shell with --non-interactive flag not set."

# now bootstrap from current letsencrypt-auto, that will install python3.6 from SCL
"$LE_AUTO" --no-self-upgrade -n --version >/dev/null 2>/dev/null

# Following test is executed in a subshell, to not leak any environment variable
(
  # enable SCL rh-python36
  . /opt/rh/rh-python36/enable

  # ensure python 3.6 is installed
  if ! python3.6 --version >/dev/null 2>/dev/null; then
    echo "ERROR: letsencrypt-auto failed to install Python3.6 using current letsencrypt-auto when only Python2.6/Python3.4 are present."
    exit 1
  fi

  echo "PASSED: Successfully upgraded to Python3.6 using current letsencrypt-auto when only Python2.6/Python3.4 are present."
)

# Following test is executed in a subshell, to not leak any environment variable
(
  export VENV_PATH=$(mktemp -d)
  "$LE_AUTO" -n --no-bootstrap --no-self-upgrade --version >/dev/null 2>&1
  if [ "$($VENV_PATH/bin/python -V 2>&1 | cut -d" " -f2 | cut -d. -f1-2)" != "3.6" ]; then
    echo "ERROR: Python 3.6 wasn't used with --no-bootstrap!"
    exit 1
  fi
)

# Following test is executed in a subshell, to not leak any environment variable
(
  # enable SCL rh-python36
  . /opt/rh/rh-python36/enable

  # ensure everything works fine with certbot-auto bootstrap when python 3.6 is already enabled
  export VENV_PATH=$(mktemp -d)
  if ! "$LE_AUTO" --no-self-upgrade -n --version >/dev/null 2>/dev/null; then
    echo "ERROR: Certbot-auto broke when Python 3.6 SCL is already enabled."
    exit 1
  fi
)

# we're going to modify env variables, so do this in a subshell
(
  # ensure CentOS6 32bits is not supported anymore, and so certbot
  # is not upgraded nor reinstalled.
  export UNAME_FAKE_32BITS=true
  OUTPUT=$("$LE_AUTO" --version 2>&1)
  if ! echo "$OUTPUT" | grep -q "Certbot will no longer receive updates."; then
    echo "ERROR: certbot-auto failed to run or upgraded pre-existing Certbot instance on 32-bit CentOS 6."
    exit 1
  fi
  if ! "$LE_AUTO" --install-only 2>&1 | grep -q "Certbot cannot be installed."; then
    echo "ERROR: certbot-auto reinstalled Certbot on 32-bit CentOS 6."
    exit 1
  fi
)

# we're going to modify env variables, so do this in a subshell
(
  # Prepare a certbot installation in the old venv path
  rm -rf /opt/eff.org
  VENV_PATH=~/.local/share/letsencrypt "$LE_AUTO" --install-only > /dev/null 2> /dev/null
  # fake 32 bits mode
  export UNAME_FAKE_32BITS=true
  OUTPUT=$("$LE_AUTO" --version 2>&1)
  if ! echo "$OUTPUT" | grep -q "Certbot will no longer receive updates."; then
    echo "ERROR: certbot-auto failed to run or upgraded pre-existing Certbot instance in the old venv path on 32-bit CentOS 6."
    exit 1
  fi
)

echo "PASSED: certbot-auto refused to install/upgrade certbot on 32-bit CentOS 6."

# test using python3
pytest -v -s certbot/letsencrypt-auto-source/tests
