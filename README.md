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

 1. Start with a Xenial VM.
 2. Install snapcraft with `snap install --classic snapcraft`.
 3. Run `git clone git://github.com/basak/certbot-snap-build -b snap-plugins/snap/certbot`.
 4. `cd certbot-snap-build`
 5. Run `git clone https://github.com/basak/certbot-snap-build -b snap-plugins/certbot certbot` (this is a workaround for #13).
 6. Run `certbot/tools/strip_hashes.py certbot/letsencrypt-auto-source/pieces/dependency-requirements.txt > certbot/constraints.txt` (this is a workaround for #13).
 7. Run `snapcraft`.
 8. Install the generated snap with `sudo snap install --dangerous --classic certbot_*_amd64.snap`. You can transfer the snap to a different machine to run it there instead if you prefer.
 9. `cd ..`
 10. `git clone git://github.com/basak/certbot-snap-build.git -b snap-plugins/snap/certbot-dns-dnsimple certbot-dns-dnsimple`
 11. `cd certbot-dns-dnsimple`
 12. `snapcraft`
 13. Install the generated snap with `sudo snap install --dangerous certbot-dns-dnsimple_*_amd64.snap`. Again, you can transfer the snap to a different machine to run it there instead if you prefer.
 14. Connect the plugin with `sudo snap connect certbot:plugin certbot-dns-dnsimple`.
 15. Now you can run Certbot as normal. For example, `certbot plugins` should display the DNSimple plugin as installed.

## Code

This proof of concept ships four git branches:

1. [This documentation](https://github.com/basak/certbot-snap-build/tree/snap-plugins/doc).
2. [A fork of Certbot upstream that adds support for
   `CERTBOT_PLUGIN_PATH`](https://github.com/basak/certbot-snap-build/tree/snap-plugins/certbot).
3. [A fork of the proof of concept Certbot snap packaging that adds plugin
   support](https://github.com/basak/certbot-snap-build/tree/snap-plugins/snap/certbot).
4. [An example of snap packaging for the Certbot DNSimple
   plugin](https://github.com/basak/certbot-snap-build/tree/snap-plugins/snap/certbot-dns-dnsimple).

If adopted, these would all be upstreamed, and no branches would be necessary.
Snap packaging is intended to be maintained within upstream code trees
themselves with the addition of `snapcraft.yaml`, much like Travis CI
integration.

## Publishing Permissions

There are security implications to permitting anyone to publish, without
review, a plugin into the Snap Store which will then run in Certbot's classic
snap context, with full access to the host system.

At a minimum, it is clear that this should happen only with the user's explicit
opt-in action.

As implemented, Certbot will only load plugins connected via the snap interface
mechanism, so permission is effectively delegated to what interface connections
the snap infrastucture will permit.

I am not clear as to exactly what is and isn't currently permitted, and what
interfaces can or cannot be set to be automatically connected.

It seems fairly clear that, at a minimum, a manual connection between snaps
coming from the same publisher will be permitted.

## Outstanding issues

[Outstanding items relating to plugin support in Certbot snaps are tracked on GitHub](https://github.com/basak/certbot-snap-build/issues?q=is%3Aissue+is%3Aopen+label%3Aplugin).
