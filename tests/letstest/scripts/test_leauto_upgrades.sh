#!/bin/bash -xe
set -o pipefail

# $OS_TYPE $PUBLIC_IP $PRIVATE_IP $PUBLIC_HOSTNAME
# are dynamically set at execution

cd letsencrypt

if ! command -v git ; then
    if [ "$OS_TYPE" = "ubuntu" ] ; then
        sudo apt-get update
    fi
    if ! (  sudo apt-get install -y git || sudo yum install -y git-all || sudo yum install -y git || sudo dnf install -y git ) ; then
        echo git installation failed!
        exit 1
    fi
fi
# If we're on a RHEL 6 based system, we can be confident Python is already
# installed because the package manager is written in Python.
if command -v python && [ $(python -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//') -eq 26 ]; then
    # 0.20.0 is the latest version of letsencrypt-auto that doesn't install
    # Python 3 on RHEL 6.
    INITIAL_VERSION="0.20.0"
    RUN_RHEL6_TESTS=1
else
    # 0.39.0 is the oldest version of letsencrypt-auto that works on CentOS 8.
    INITIAL_VERSION="0.39.0"
fi

git checkout -f "v$INITIAL_VERSION" letsencrypt-auto
if ! ./letsencrypt-auto -v --debug --version --no-self-upgrade 2>&1 | tail -n1 | grep "^certbot $INITIAL_VERSION$" ; then
    echo initial installation appeared to fail
    exit 1
fi

if command -v python; then
    PYTHON_NAME="python"
else
    PYTHON_NAME="python3"
fi

# Now that python and openssl have been installed, we can set up a fake server
# to provide a new version of letsencrypt-auto. First, we start the server and
# directory to be served.
MY_TEMP_DIR=$(mktemp -d)
PORT_FILE="$MY_TEMP_DIR/port"
LOG_FILE="$MY_TEMP_DIR/log"
SERVER_PATH=$("$PYTHON_NAME" tools/readlink.py tools/simple_http_server.py)
cd "$MY_TEMP_DIR"
# We set PYTHONUNBUFFERED to disable buffering of output to LOG_FILE
PYTHONUNBUFFERED=1 "$PYTHON_NAME" "$SERVER_PATH" 0 > $PORT_FILE 2> "$LOG_FILE" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" && rm -rf "$MY_TEMP_DIR"' EXIT
cd ~-

# Then, we set up the files to be served.
FAKE_VERSION_NUM="99.99.99"
echo "{\"releases\": {\"$FAKE_VERSION_NUM\": null}}" > "$MY_TEMP_DIR/json"
LE_AUTO_SOURCE_DIR="$MY_TEMP_DIR/v$FAKE_VERSION_NUM"
NEW_LE_AUTO_PATH="$LE_AUTO_SOURCE_DIR/letsencrypt-auto"
mkdir "$LE_AUTO_SOURCE_DIR"
cp letsencrypt-auto-source/letsencrypt-auto "$LE_AUTO_SOURCE_DIR/letsencrypt-auto"
SIGNING_KEY="letsencrypt-auto-source/tests/signing.key"
openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$NEW_LE_AUTO_PATH.sig" "$NEW_LE_AUTO_PATH"

# Next, we wait for the server to start and get the port number.
sleep 5s
SERVER_PORT=$(sed -n 's/.*port \([0-9]\+\).*/\1/p' "$PORT_FILE")

# Finally, we set the necessary certbot-auto environment variables.
export LE_AUTO_DIR_TEMPLATE="http://localhost:$SERVER_PORT/%s/"
export LE_AUTO_JSON_URL="http://localhost:$SERVER_PORT/json"
export LE_AUTO_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMoSzLYQ7E1sdSOkwelg
tzKIh2qi3bpXuYtcfFC0XrvWig071NwIj+dZiT0OLZ2hPispEH0B7ISuuWg1ll7G
hFW0VdbxL6JdGzS2ShNWkX9hE9z+j8VqwDPOBn3ZHm03qwpYkBDwQib3KqOdYbTT
uUtJmmGcuk3a9Aq/sCT6DdfmTSdP5asdQYwIcaQreDrOosaS84DTWI3IU+UYJVgl
LsIVPBuy9IcgHidUQ96hJnoPsDCWsHwX62495QKEarauyKQrJzFes0EY95orDM47
Z5o/NDiQB11m91yNB0MmPYY9QSbnOA9j7IaaC97AwRLuwXY+/R2ablTcxurWou68
iQIDAQAB
-----END PUBLIC KEY-----
"

if [ "$RUN_RHEL6_TESTS" = 1 ]; then
    if command -v python3; then
        echo "Didn't expect Python 3 to be installed!"
        exit 1
    fi
    cp letsencrypt-auto cb-auto
    if ! ./cb-auto -v --debug --version 2>&1 | grep "$INITIAL_VERSION" ; then
        echo "Certbot shouldn't have updated to a new version!"
        exit 1
    fi
    # Create a 2nd venv at the old path to ensure we properly handle the (unlikely) case of two separate virtual environments below.
    HOME=${HOME:-~root}
    XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
    OLD_VENV_PATH="$XDG_DATA_HOME/letsencrypt"
    export VENV_PATH="$OLD_VENV_PATH"
    if ! sudo -E ./letsencrypt-auto -v --debug --version --no-self-upgrade 2>&1 | tail -n1 | grep "^certbot $INITIAL_VERSION$" ; then
        echo second installation appeared to fail
        exit 1
    fi
    unset VENV_PATH
fi

if ./letsencrypt-auto -v --debug --version | grep "WARNING: couldn't find Python" ; then
    echo "Had problems checking for updates!"
    exit 1
fi

# Since certbot-auto is deprecated, we expect it to leave existing Certbot
# installations unmodified so we check for the same version that was initially
# installed below.
EXPECTED_VERSION="$INITIAL_VERSION"

if ! /opt/eff.org/certbot/venv/bin/letsencrypt --version 2>&1 | tail -n1 | grep "^certbot $EXPECTED_VERSION$" ; then
    echo unexpected certbot version found
    exit 1
fi

if ! diff letsencrypt-auto letsencrypt-auto-source/letsencrypt-auto ; then
    echo letsencrypt-auto and letsencrypt-auto-source/letsencrypt-auto differ
    exit 1
fi

# Now let's test if letsencrypt-auto still tries to upgrade to a new version.
# Regardless of the OS, versions of the script with development version numbers
# ending in .dev0 will not upgrade. See
# https://github.com/certbot/certbot/blob/bdfb9f19c4086a60ef010d2431768850c26d838a/certbot-auto#L1947-L1948.
# In order to test the process of different OSes setting NO_SELF_UPGRADE as
# part of the script's deprecation, we make use of the fact that
# letsencrypt-auto should still attempt to fetch the version number from PyPI
# even if it has a development version number unless NO_SELF_UPGRADE is set in
# which case all of that logic should be skipped.
#
# First we make a copy of the current server logs.
PREVIOUS_LOG_FILE="$MY_TEMP_DIR/previous-log"
cp "$LOG_FILE" "$PREVIOUS_LOG_FILE"

# Next we run letsencrypt-auto and make sure there were no problems checking
# for updates, the Certbot install still works, the version number is what
# we expect, and it prints a message about not receiving updates.
if ./letsencrypt-auto -v --debug --version | grep "WARNING: couldn't find Python" ; then
    echo "Had problems checking for updates!"
    exit 1
fi
if ! ./letsencrypt-auto -v --debug --version 2>&1 | tail -n1 | grep "^certbot $EXPECTED_VERSION$" ; then
    echo unexpected certbot version found
    exit 1
fi
if ! ./letsencrypt-auto -v --debug --version 2>&1 | grep "will no longer receive updates" ; then
    echo script did not print warning about not receiving updates!
    exit 1
fi

# Finally, we check if our local server received more requests. Over time,
# we'll move more and more OSes into this case until it this is the expected
# behavior on all systems.
if [ -f /etc/issue ] && grep -iq "Amazon Linux" /etc/issue; then
    if ! diff "$LOG_FILE" "$PREVIOUS_LOG_FILE" ; then
        echo our local server received unexpected requests
        exit 1
    fi
else
    if diff "$LOG_FILE" "$PREVIOUS_LOG_FILE" ; then
        echo our local server did not receive the requests we expected
        exit 1
    fi
fi
