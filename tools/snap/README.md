# Building Certbot Snaps

## Local Testing and Development

These instructions are recommended when testing anything about the snap setup for ease of debugging.
The architecture of the built snap is limited to the architecture of the system it is built on.

### Initial VM Set Up

These steps need to be done once to set up your VM and do not need to be run again to rebuild the snap.

 1. Start with a Focal VM. You need a full virtual machine using something like DigitalOcean, EC2, or VirtualBox. Docker won't work. Another version of Ubuntu can probably be used, but Focal was used when writing these instructions.
 2. Set up a user other than root with sudo privileges for use with snapcraft and run all of the following commands with it. A command to do this for a user named certbot looks like `adduser certbot && usermod -aG sudo certbot && su - certbot`.
 3. Install git and python with `sudo apt update && sudo apt install -y git python`.
 4. Set up lxd for use with snapcraft by running `sudo snap install lxd && sudo /snap/bin/lxd.migrate -yes; sudo /snap/bin/lxd waitready && sudo /snap/bin/lxd init --auto` (errors here are ok; it may already
 have been installed on your system).
 5. Add your current user to the lxd group and update your shell to have the new assignment by running `sudo usermod -a -G lxd ${USER} && newgrp lxd`.
 6. Install snapcraft with `sudo snap install --classic snapcraft`.
 7. `cd ~` (or any other directory where you want our source files to be)
 8. Run `git clone https://github.com/certbot/certbot`
 9. `cd certbot` (All further instructions are relative to this directory.)

### Certbot Snap

#### Reset the Environment

If the snap has been built before, the instructions below clean up the build environment so it can reliably be used again.

 1. `snapcraft clean --use-lxd`
 2. [Optional] `mv certbot_*_amd64.snap certbot_amd64.snap.bak`

#### Build the Certbot Snap

These are the steps to build and install the Certbot snap. If you have run these steps before, you may want to run the commands in the section above to clean things up or save a previous build before building the snap again (running `snapcraft` again will overwrite the previous snap).

 1. Run `snapcraft --use-lxd`.
 2. Install the generated snap with `sudo snap install --dangerous --classic certbot_*_amd64.snap`. You can transfer the snap to a different machine to run it there instead if you prefer.

#### Run

Run Certbot as normal. For example, `certbot plugins` should display the Apache and Nginx plugins.

### Certbot Plugin Snaps

These instructions use the `certbot-dns-dnsimple` plugin as an example, but all of Certbot's other plugin snaps can be built in the same way.

#### Reset the Environment

If the plugin snap has been built before, the instructions below clean up the build environment so it can reliably be used again.

 1. `cd certbot-dns-dnsimple`
 2. `snapcraft clean --use-lxd`
 3. [Optional] `mv certbot-dns-dnsimple_*_amd64.snap certbot-dns-simple_amd64.snap.bak`
 4. `cd ..`

#### Build a Certbot Plugin Snap

These are the steps to build and install the Certbot DNSimple plugin snap. If you have run these steps before, you may want to run the commands in the section above to clean things up or save a previous build before building the snap again (running `snapcraft` again will overwrite the previous snap).

 1. Run `tools/snap/generate_dnsplugins_all.sh` to generate all necessary files for all plugin snaps.
 2. `cd certbot-dns-dnsimple`
 3. `snapcraft --use-lxd`
 4. Run `sudo snap set certbot trust-plugin-with-root=ok`.
 5. Install the generated snap with `sudo snap install --dangerous certbot-dns-dnsimple_*_amd64.snap`. Again, you can transfer the snap to a different machine to run it there instead if you prefer.
 6. Connect the plugin with `sudo snap connect certbot:plugin certbot-dns-dnsimple`.
 7. Connect the plugin metadata with `sudo snap connect certbot-dns-dnsimple:certbot-metadata certbot:certbot-metadata`. Install the plugin again to test refresh; if the plugin's hook creates any logs, they are at `/var/snap/certbot-dns-dnsimple/current/debuglog`.

#### Run

Run Certbot as normal. For example, `certbot plugins` should display the DNSimple plugin as installed.

## Building for Other Architectures

To build for an unavailable architecture or for multiple architectures simultaneously, we recommend using snapcraft's remote build feature.
It is easiest to run this from a local machine.

### Initial Local Setup

 1. Create or log into an Ubuntu One account [here](https://login.launchpad.net/).
 2. Install git and python with `sudo apt update && sudo apt install -y git python`.
 3. Install snapcraft with `sudo snap install --classic snapcraft`.
 4. `cd ~` (or any other directory where you want our source files to be)
 5. Run `git clone https://github.com/certbot/certbot`
 6. `cd certbot` (All further instructions are relative to this directory.)
 7. To trigger `snapcraft` to request access to your Launchpad account, run
    `snapcraft remote-build --launchpad-accept-public-upload --status`. A URL where you need
    to grant this access will be printed to your terminal and automatically open in your browser
    if one is available.

### Build Snaps Remotely

Certbot provides a wrapper around snapcraft's remote build to make building all of our plugins easier. To see all available
options, run `python3 tools/snap/build_remote.py --help`.

For example, to build all available snaps for all architectures, run `python3 tools/snap/build_remote.py ALL --archs amd64 arm64 armhf`.

To build only the certbot snap on only amd64, run `python3 tools/snap/build_remote.py certbot --archs armhf`.

The command will upload the entire contents of the working directory, so if the remote build
appears to hang, try using a clean clone of the `certbot` repository.
