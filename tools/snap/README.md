# Certbot Snaps

## Local Testing and Development

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
