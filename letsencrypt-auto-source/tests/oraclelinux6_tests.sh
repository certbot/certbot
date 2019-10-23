#!/bin/bash
# Start by making sure your system is up-to-date:
yum update -y >/dev/null

LE_AUTO_PY_34="certbot/letsencrypt-auto-source/letsencrypt-auto_py_34"
LE_AUTO="certbot/letsencrypt-auto-source/letsencrypt-auto"

# Check bootstrap from current letsencrypt-auto will fail, because SCL is not enabled.
if ! "$LE_AUTO" -n 2>&1 | grep -q "Enable the SCL repository and try running Certbot again."; then
  echo "ERROR: Bootstrap was not aborted although SCL was not installed!"
  exit 1
fi

echo "PASSED: Bootstrap was aborted since SCL was not installed."

# Bootstrap from the old letsencrypt-auto, Python 3.4 will be installed from EPEL.
"$LE_AUTO_PY_34" --no-self-upgrade -n >/dev/null 2>/dev/null

# Ensure Python 3.4 is installed
python3.4 --version >/dev/null 2>/dev/null
RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: old letsencrypt-auto failed to install Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."
  exit 1
fi

echo "PASSED: Bootstrap from old letsencrypt-auto succeeded and installed Python 3.4"

# Expect letsencrypt-auto to skip rebootstrapping with a warning since SCL is not installed.
if ! "$LE_AUTO" --non-interactive --version 2>&1 | grep -q "This requires manual user intervention"; then
  echo "FAILED: Script letsencrypt-auto managed to start Certbot in interactive shell while SCL is not enabled!"
  exit 1
fi

echo "PASSED: Script letsencrypt-auto did not rebootstrap."

# Enable SCL
yum install -y oracle-softwarecollection-release-el6 >/dev/null


# Expect letsencrypt-auto to bootstrap successfully since SCL is available.
"$LE_AUTO" -n --version >/dev/null 2>/dev/null

if [ "$(/opt/eff.org/certbot/venv/bin/python -V 2>&1 | cut -d" " -f2 | cut -d. -f1-2)" != "3.6" ]; then
  echo "ERROR: Script letsencrypt-auto failed to bootstrap and install Python 3.6 while SCL is available."
  exit 1
fi

if ! /opt/eff.org/certbot/venv/bin/certbot --version > /dev/null 2> /dev/null; then
  echo "ERROR: Script letsencrypt-auto did not install certbot correctly while SCL is enabled."
  exit 1
fi

echo "PASSED: Script letsencrypt-auto correctly bootstraped Certbot using rh-python36 when SCL is available."
