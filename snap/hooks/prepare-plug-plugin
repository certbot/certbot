#!/bin/sh -e

# Workaround for a very old snapctl binary on the host connecting to the wrong socket and crashing.
# Prefer an up-to-date snapctl from the core or snapd snaps, if they exist. We ask users to install
# the core snap in the Certbot installation instructions.
# See https://github.com/certbot/certbot/issues/8922, https://bugs.launchpad.net/snapd/+bug/1933392
SNAPCTL_CORE="/snap/core/current/usr/bin/snapctl"
SNAPCTL_SNAPD="/snap/snapd/current/usr/bin/snapctl"
SNAPCTL="snapctl"
if [ -x $SNAPCTL_CORE ]; then
    SNAPCTL=$SNAPCTL_CORE
elif [ -x $SNAPCTL_SNAPD ]; then
    SNAPCTL=$SNAPCTL_SNAPD
fi

if [ "$($SNAPCTL get trust-plugin-with-root)" = "ok" ]; then
    # allow the connection, but reset config to allow for other slots to go through this auth flow
    $SNAPCTL unset trust-plugin-with-root
    exit 0
else
    echo "Only connect this interface if you trust the plugin author to have root on the system."
    echo "Run \`snap set $SNAP_NAME trust-plugin-with-root=ok\` to acknowledge this and then run this command again to perform the connection."
    echo "If that doesn't work, you may need to remove all certbot-dns-* plugins from the system, then try installing the certbot snap again."
    exit 1
fi
