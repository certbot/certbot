#!/bin/bash -e
# Release packages to PyPI

if [ "`dirname $0`" != "tools" ] ; then
    echo Please run this script from the repo root
    exit 1
fi

CheckVersion() {
    # Args: <version number>
    if ! echo "$1" | grep -q -e '[0-9]\+.[0-9]\+.[0-9]\+' ; then
        echo "$1 doesn't look like 1.2.3"
        echo "Usage:"
        echo "$0 RELEASE_VERSION NEXT_VERSION"
        exit 1
    fi
}

CheckVersion "$1"
CheckVersion "$2"

if [ "$RELEASE_GPG_KEY" = "" ] && ! gpg2 --card-status >/dev/null 2>&1; then
    echo OpenPGP card not found!
    echo Please insert your PGP card and run this script again.
    exit 1
fi

if ! command -v script >/dev/null 2>&1; then
    echo The command script was not found.
    echo Please install it.
    exit 1
fi

if [ -n "${SNAP_BUILD+x}" ]; then
    echo "Running the release script with the environment variable SNAP_BUILD"
    echo "set will cause plugins' wheels to be built without dependencies"
    echo "on Certbot. See https://github.com/certbot/certbot/pull/8091 for more"
    echo "info. Please unset this environment variable and run this script"
    echo "again."
    exit 1
fi

export RELEASE_DIR="./releases"
mv "$RELEASE_DIR" "$RELEASE_DIR.$(date +%s).bak" || true
LOG_PATH="log"
mv "$LOG_PATH" "$LOG_PATH.$(date +%s).bak" || true

# Work with both Linux and macOS versions of script
if script --help | grep -q -- '--command'; then
    script --command "tools/_release.sh $1 $2" "$LOG_PATH"
else
    script "$LOG_PATH" tools/_release.sh "$1" "$2"
fi
