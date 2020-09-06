# Certbot Plugin Snaps

This is a proof of concept of how a Certbot snap might support plugin snaps
that add functionality to Certbot using its existing plugin API.

## Architecture

This is a description of how Certbot plugin functionality is exposed via snaps.
For information on Certbot's plugin architecture itself, see the [Certbot
documentation on
plugins](https://certbot.eff.org/docs/contributing.html#plugin-architecture).

The Certbot snap itself is a classic snap. Plugin snaps are regular confined
snaps, but normally do not provide any "apps" themselves. Plugin snaps export
loadable Python modules to the Certbot snap via a snap content interface.

Certbot itself accepts a `CERTBOT_PLUGIN_PATH` environment variable. This
support is currently patched but this is intended to be upstreamed. The
variable, if set, should contain a `:`-separated list of paths to add to
Certbot's plugin search path.

The Certbot snap runs Certbot via a wrapper which examines its list of
connected interfaces, sets `CERTBOT_PLUGIN_PATH` accordingly, and then `exec`s
Certbot itself.

## Use (Production)

_Note: this production use example assumes that these snaps are available in
stable channels in the Snap Store, which they aren't yet. See below for
development instructions._

To use a Certbot plugin snap, install both the plugin snap and the Certbot snap
as usual. Plugin snaps are confined as normal; the Certbot snap is a classic
snap and thus needs `--classic` during installation. For example:

    snap install --classic certbot
    snap set certbot trust-plugin-with-root=ok
    snap install certbot-dns-dnsimple

Then connect the plugin snap to the main certbot snap as follows. Note that
this connection allows the plugin snap code to run inside the certbot process,
which has access to your host system. Only perform this step if you trust the
plugin author to have "root" on your system.

    sudo snap connect certbot:plugin certbot-dns-dnsimple

Now certbot will automatically load and use the plugin when it is run. To check
that this has worked, `certbot plugins` should list the plugin.

You can now operate the plugin as normal.

## Use (Testing and Development)

To try this out, you'll need to build the snaps (a patched Certbot snap and a
plugin snap) manually.

### Initial VM Set Up

These steps need to be done once to set up your VM and do not need to be run again to rebuild the snap.

 1. Start with a Focal VM. You need a full virtual machine using something like DigitalOcean, EC2, or VirtualBox. Docker won't work. Another version of Ubuntu can probably be used, but Focal was used when writing these instructions.
 2. Set up a user other than root with sudo privileges for use with snapcraft and run all of the following commands with it. A command to do this for a user named certbot looks like `adduser certbot && usermod -aG sudo certbot && su - certbot`.
 3. Install git and python with `sudo apt update && sudo apt install -y git python`.
 4. Set up lxd for use with snapcraft by running `sudo snap install lxd && sudo /snap/bin/lxd.migrate -yes && sudo /snap/bin/lxd waitready && sudo /snap/bin/lxd init --auto` (errors here are ok; it may already
 have been installed on your system).
 5. Add your current user to the lxd group and update your shell to have the new assignment by running `sudo usermod -a -G lxd ${USER} && newgrp lxd`.
 6. Install snapcraft with `sudo snap install --classic snapcraft`.
 7. `cd ~` (or any other directory where you want our source files to be)
 8. Run `git clone git://github.com/certbot/certbot`
 9. `cd certbot`

### Build the Snaps

These are the steps to build and install the snaps. If you have run these steps before, you may want to run the commands in the section below to clean things up before building the snap again.

 1. Run `snapcraft --use-lxd`.
 2. Install the generated snap with `sudo snap install --dangerous --classic certbot_*_amd64.snap`. You can transfer the snap to a different machine to run it there instead if you prefer.
 3. Run `tools/merge_requirements.py tools/dev_constraints.txt <(tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt) > certbot-dns-dnsimple/snap-constraints.txt` (this is a workaround for https://github.com/certbot/certbot/issues/8100).
 4. `cd certbot-dns-dnsimple`
 5. `snapcraft --use-lxd`
 6. Run `sudo snap set certbot trust-plugin-with-root=ok`.
 7. Install the generated snap with `sudo snap install --dangerous certbot-dns-dnsimple_*_amd64.snap`. Again, you can transfer the snap to a different machine to run it there instead if you prefer.
 8. Connect the plugin with `sudo snap connect certbot:plugin certbot-dns-dnsimple`.
 9. Connect the plugin metadata with `sudo snap connect certbot-dns-dnsimple:certbot-metadata certbot:certbot-metadata`. Install the plugin again to test refresh; logs are at `/var/snap/certbot-dns-dnsimple/current/debuglog`.
 10. Now you can run Certbot as normal. For example, `certbot plugins` should display the DNSimple plugin as installed.

### Reset the Environment

The instructions below clean up the build environment so it can reliably be used again.

1. `cd ~/certbot` (or to an alternate path where you put our source files)
2. `snapcraft clean --use-lxd`
3. `rm certbot_*_amd64.snap`
4. `cd certbot-dns-dnsimple`
5. `rm certbot-dns-dnsimple_*_amd64.snap`
6. `snapcraft clean --use-lxd`
7. `cd ..`

## Publishing Permissions

There are security implications to permitting anyone to publish, without
review, a plugin into the Snap Store which will then run in Certbot's classic
snap context, with full access to the host system.

At a minimum, it is clear that this should happen only with the user's explicit
opt-in action.

As implemented, Certbot will only load plugins connected via the snap interface
mechanism, so permission is effectively delegated to what interface connections
the snap infrastucture will permit.

We have approval from the snap team to use this design as long as we make it
explicit what a user is agreeing to when they connect a plugin to the
Certbot snap. That work was completed in
https://github.com/certbot/certbot/issues/8013.

## Outstanding issues

[Outstanding items relating to plugin support in Certbot snaps are tracked on GitHub](https://github.com/certbot/certbot/issues?q=is%3Aopen+is%3Aissue+label%3A%22area%3A+snaps%22).
