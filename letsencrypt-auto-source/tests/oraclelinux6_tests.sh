#!/bin/bash
set -eo pipefail
# Start by making sure your system is up-to-date:
yum update -y >/dev/null

LE_AUTO_PY_34="certbot/letsencrypt-auto-source/letsencrypt-auto_py_34"
LE_AUTO="certbot/letsencrypt-auto-source/letsencrypt-auto"

# Apply installation instructions from official documentation:
# https://certbot.eff.org/lets-encrypt/centosrhel6-other
cp "$LE_AUTO" /usr/local/bin/certbot-auto
chown root /usr/local/bin/certbot-auto
chmod 0755 /usr/local/bin/certbot-auto
LE_AUTO=/usr/local/bin/certbot-auto

# Last version of certbot-auto that was bootstraping Python 3.4 for CentOS 6 users
INITIAL_CERTBOT_VERSION_PY34="certbot 0.38.0"

# Check bootstrap from current certbot-auto will fail, because SCL is not enabled.
set +o pipefail
if ! "$LE_AUTO" -n 2>&1 | grep -q "Enable the SCL repository and try running Certbot again."; then
  echo "ERROR: Bootstrap was not aborted although SCL was not installed!"
  exit 1
fi
set -o pipefail

echo "PASSED: Bootstrap was aborted since SCL was not installed."

# Bootstrap from the old letsencrypt-auto, Python 3.4 will be installed from EPEL.
"$LE_AUTO_PY_34" --no-self-upgrade -n --install-only >/dev/null 2>/dev/null

# Ensure Python 3.4 is installed
if ! command -v python3.4 &>/dev/null; then
  echo "ERROR: old letsencrypt-auto failed to install Python3.4 using letsencrypt-auto < 0.37.0 when only Python2.6 is present."
  exit 1
fi

echo "PASSED: Bootstrap from old letsencrypt-auto succeeded and installed Python 3.4"

# Expect certbot-auto to skip rebootstrapping with a warning since SCL is not installed.
if ! "$LE_AUTO" --non-interactive --version 2>&1 | grep -q "This requires manual user intervention"; then
  echo "FAILED: Script certbot-auto did not print a warning about needing manual intervention!"
  exit 1
fi

echo "PASSED: Script certbot-auto did not rebootstrap."

# NB: Readline has an issue on all Python versions for OL 6, making `certbot --version`
# output an unprintable ASCII character on a new line at the end.
# So we take the second last line of the output.
version=$($LE_AUTO --version 2>/dev/null | tail -2 | head -1)

if [ "$version" != "$INITIAL_CERTBOT_VERSION_PY34" ]; then
  echo "ERROR: Script certbot-auto upgraded certbot in a non-interactive shell while SCL was not enabled."
  exit 1
fi

echo "PASSED: Script certbot-auto did not upgrade certbot but started it successfully while SCL was not enabled."

# Enable SCL
yum install -y oracle-softwarecollection-release-el6 >/dev/null

# Expect certbot-auto to bootstrap successfully since SCL is available.
"$LE_AUTO" -n --version &>/dev/null

if [ "$(/opt/eff.org/certbot/venv/bin/python -V 2>&1 | cut -d" " -f2 | cut -d. -f1-2)" != "3.6" ]; then
  echo "ERROR: Script certbot-auto failed to bootstrap and install Python 3.6 while SCL is available."
  exit 1
fi

if ! /opt/eff.org/certbot/venv/bin/certbot --version > /dev/null 2> /dev/null; then
  echo "ERROR: Script certbot-auto did not install certbot correctly while SCL is enabled."
  exit 1
fi

echo "PASSED: Script certbot-auto correctly bootstraped Certbot using rh-python36 when SCL is available."

# Expect certbot-auto will be totally silent now that everything has been correctly boostraped.
OUTPUT_LEN=$("$LE_AUTO" --install-only --no-self-upgrade --quiet 2>&1 | wc -c)
if [ "$OUTPUT_LEN" != 0 ]; then
    echo certbot-auto produced unexpected output!
    exit 1
fi

echo "PASSED: Script certbot-auto did not print anything in quiet mode."
