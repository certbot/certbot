# Certbot change log

Certbot adheres to [Semantic Versioning](http://semver.org/).

## 0.13.0 - 2017-04-06

### Added

* `--debug-challenges` now pauses Certbot after setting up challenges for debugging.
* The Nginx parser can now handle all valid directives in configuration files.
* Nginx ciphersuites have changed to Mozilla Intermediate.
* `certbot-auto --no-bootstrap` provides the option to not install OS dependencies.

### Fixed

* `--register-unsafely-without-email` now respects `--quiet`.
* Hyphenated renewal parameters are now saved in renewal config files.
* `--dry-run` no longer persists keys and csrs.
* Certbot no longer hangs when trying to start Nginx in Arch Linux.
* Apache rewrite rules no longer double-encode characters.

A full list of changes is available on GitHub:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.13.0%20is%3Aclosed%20

## 0.12.0 - 2017-03-02

### Added

* Certbot now allows non-camelcase Apache VirtualHost names.
* Certbot now allows more log messages to be silenced.

### Fixed

* Fixed a regression around using `--cert-name` when getting new certificates

More information about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.12.0

## 0.11.1 - 2017-02-01

### Fixed

* Resolved a problem where Certbot would crash while parsing command line
arguments in some cases.
* Fixed a typo.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/pulls?q=is%3Apr%20milestone%3A0.11.1%20is%3Aclosed

## 0.11.0 - 2017-02-01

### Added

* When using the standalone plugin while running Certbot interactively 
and a required port is bound by another process, Certbot will give you
the option to retry to grab the port rather than immediately exiting.
* You are now able to deactivate your account with the Let's Encrypt
server using the `unregister` subcommand.
* When revoking a certificate using the `revoke` subcommand, you now
have the option to provide the reason the certificate is being revoked
to Let's Encrypt with `--reason`.

### Changed

* Providing `--quiet` to `certbot-auto` now silences package manager output.

### Removed

* Removed the optional `dnspython` dependency in our `acme` package.
Now the library does not support client side verification of the DNS
challenge.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.11.0+is%3Aclosed

## 0.10.2 - 2017-01-25

### Added

* If Certbot receives a request with a `badNonce` error, it now
automatically retries the request. Since nonces from Let's Encrypt expire,
this helps people performing the DNS challenge with the `manual` plugin
who may have to wait an extended period of time for their DNS changes to
propagate.

### Fixed

* Certbot now saves the `--preferred-challenges` values for renewal. Previously
these values were discarded causing a different challenge type to be used when
renewing certs in some cases.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.2+is%3Aclosed

## 0.10.1 - 2017-01-13

### Fixed

* Resolve problems where when asking Certbot to update a certificate at
an existing path to include different domain names, the old names would
continue to be used.
* Fix issues successfully running our unit test suite on some systems.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.1+is%3Aclosed

## 0.10.0 - 2017-01-11

## Added

* Added the ability to customize and automatically complete DNS and HTTP
domain validation challenges with the manual plugin. The flags
`--manual-auth-hook` and `--manual-cleanup-hook` can now be provided
when using the manual plugin to execute commands provided by the user to
perform and clean up challenges provided by the CA. This is best used in
complicated setups where the DNS challenge must be used or Certbot's
existing plugins cannot be used to perform HTTP challenges. For more
information on how this works, see `certbot --help manual`.
* Added a `--cert-name` flag for specifying the name to use for the
certificate in Certbot's configuration directory. Using this flag in
combination with `-d/--domains`, a user can easily request a new
certificate with different domains and save it with the name provided by
`--cert-name`. Additionally, `--cert-name` can be used to select a
certificate with the `certonly` and `run` subcommands so a full list of
domains in the certificate does not have to be provided.
* Added subcommand `certificates` for listing the certificates managed by
Certbot and their properties.
* Added the `delete` subcommand for removing certificates managed by Certbot
from the configuration directory.
* Certbot now supports requesting internationalized domain names (IDNs).
* Hooks provided to Certbot are now saved to be reused during renewal.
If you run Certbot with `--pre-hook`, `--renew-hook`, or `--post-hook`
flags when obtaining a certificate, the provided commands will
automatically be saved and executed again when renewing the certificate.
A pre-hook and/or post-hook can also be given to the `certbot renew`
command either on the command line or in a [configuration
file](https://certbot.eff.org/docs/using.html#configuration-file) to run
an additional command before/after any certificate is renewed. Hooks
will only be run if a certificate is renewed.
* Support Busybox in certbot-auto.

### Changed

* Recategorized `-h/--help` output to improve documentation and
discoverability.

### Removed

* Removed the ncurses interface. This change solves problems people
were having on many systems, reduces the number of Certbot
dependencies, and simplifies our code. Certbot's only interface now is
the text interface which was available by providing `-t/--text` to
earlier versions of Certbot.

### Fixed

* Many small bug fixes.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.0is%3Aclosed

## 0.9.3 - 2016-10-13

### Added

* The Apache plugin uses information about your OS to help determine the
layout of your Apache configuration directory. We added a patch to
ensure this code behaves the same way when testing on different systems
as the tests were failing in some cases.

### Changed

* Certbot adopted more conservative behavior about reporting a needed port as
unavailable when using the standalone plugin.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/27?closed=1

## 0.9.2 - 2016-10-12

### Added

* Certbot stopped requiring that all possibly required ports are available when
using the standalone plugin. It now only verifies that the ports are available
when they are necessary.

### Fixed

* Certbot now verifies that our optional dependencies version matches what is
required by Certbot.
* Certnot now properly copies the `ssl on;` directives as necessary when
performing domain validation in the Nginx plugin.
* Fixed problem where symlinks were becoming files when they were
packaged, causing errors during testing and OS packaging.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/26?closed=1

## 0.9.1 - 2016-10-06

### Fixed

* Fixed a bug that was introduced in version 0.9.0 where the command
line flag -q/--quiet wasn't respected in some cases.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/25?closed=1

## 0.9.0 - 2016-10-05

### Added

* Added an alpha version of the Nginx plugin. This plugin fully automates the
process of obtaining and installing certificates with Nginx.
Additionally, it is able to automatically configure security
enhancements such as an HTTP to HTTPS redirect and OCSP stapling. To use
this plugin, you must have the `certbot-nginx` package installed (which
is installed automatically when using `certbot-auto`) and provide
`--nginx` on the command line. This plugin is still in its early stages
so we recommend you use it with some caution and make sure you have a
backup of your Nginx configuration.
* Added support for the `DNS` challenge in the `acme` library and `DNS` in
Certbot's `manual` plugin. This allows you to create DNS records to
prove to Let's Encrypt you control the requested domain name. To use
this feature, include `--manual --preferred-challenges dns` on the
command line.
* Certbot now helps with enabling Extra Packages for Enterprise Linux (EPEL) on
CentOS 6 when using `certbot-auto`. To use `certbot-auto` on CentOS 6,
the EPEL repository has to be enabled. `certbot-auto` will now prompt
users asking them if they would like the script to enable this for them
automatically. This is done without prompting users when using
`letsencrypt-auto` or if `-n/--non-interactive/--noninteractive` is
included on the command line.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.9.0+is%3Aclosed

## 0.8.1 - 2016-06-14

### Added

* Certbot now preserves a certificate's common name when using `renew`.
* Certbot now saves webroot values for renewal when they are entered interactively.
* Certbot now gracefully reports that the Apache plugin isn't usable when Augeas is not installed.
* Added experimental support for Mageia has been added to `certbot-auto`.

### Fixed

* Fixed problems with an invalid user-agent string on OS X.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.8.1+

## 0.8.0 - 2016-06-02

### Added

* Added the `register` subcommand which can be used to register an account
with the Let's Encrypt CA.
* You can now run `certbot register --update-registration` to
change the e-mail address associated with your registration.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.8.0+

## 0.7.0 - 2016-05-27

### Added

* Added `--must-staple` to request certificates from Let's Encrypt
with the OCSP must staple extension.
* Certbot now automatically configures OSCP stapling for Apache.
* Certbot now allows requesting certificates for domains found in the common name
of a custom CSR.

### Fixed

* Fixed a number of miscellaneous bugs

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=milestone%3A0.7.0+is%3Aissue

## 0.6.0 - 2016-05-12

### Added

* Versioned the datetime dependency in setup.py.

### Changed

* Renamed the client from `letsencrypt` to `certbot`.

### Fixed

* Fixed a small json deserialization error.
* Certbot now preserves domain order in generated CSRs.
* Fixed some minor bugs.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.6.0%20is%3Aclosed%20

## 0.5.0 - 2016-04-05

### Added

* Added the ability to use the webroot plugin interactively.
* Added the flags --pre-hook, --post-hook, and --renew-hook which can be used with
the renew subcommand to register shell commands to run in response to
renewal events. Pre-hook commands will be run before any certs are
renewed, post-hook commands will be run after any certs are renewed,
and renew-hook commands will be run after each cert is renewed. If no
certs are due for renewal, no command is run.
* Added a -q/--quiet flag which silences all output except errors.
* Added an --allow-subset-of-domains flag which can be used with the renew
command to prevent renewal failures for a subset of the requested
domains from causing the client to exit.

### Changed

* Certbot now uses renewal configuration files. In /etc/letsencrypt/renewal
by default, these files can be used to control what parameters are
used when renewing a specific certificate.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=milestone%3A0.5.0+is%3Aissue

## 0.4.2 - 2016-03-03

### Fixed

* Resolved problems encountered when compiling letsencrypt
against the new OpenSSL release.
* Fixed problems encountered when using `letsencrypt renew` with configuration files
from the private beta.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.4.2

## 0.4.1 - 2016-02-29

### Fixed

* Fixed Apache parsing errors encountered with some configurations.
* Fixed Werkzeug dependency problems encountered on some Red Hat systems.
* Fixed bootstrapping failures when using letsencrypt-auto with --no-self-upgrade.
* Fixed problems with parsing renewal config files from private beta.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is:issue+milestone:0.4.1

## 0.4.0 - 2016-02-10

### Added

* Added the verb/subcommand `renew` which can be used to renew your existing
certificates as they approach expiration. Running `letsencrypt renew`
will examine all existing certificate lineages and determine if any are
less than 30 days from expiration. If so, the client will use the
settings provided when you previously obtained the certificate to renew
it. The subcommand finishes by printing a summary of which renewals were
successful, failed, or not yet due.
* Added a `--dry-run` flag to help with testing configuration
without affecting production rate limits. Currently supported by the
`renew` and `certonly` subcommands, providing `--dry-run` on the command
line will obtain certificates from the staging server without saving the
resulting certificates to disk.
* Added major improvements to letsencrypt-auto. This script
has been rewritten to include full support for Python 2.6, the ability
for letsencrypt-auto to update itself, and improvements to the
stability, security, and performance of the script.
* Added support for Apache 2.2 to the Apache plugin.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.4.0

## 0.3.0 - 2016-01-27

### Added

* Added a non-interactive mode which can be enabled by including `-n` or
`--non-interactive` on the command line. This can be used to guarantee
the client will not prompt when run automatically using cron/systemd.
* Added preparation for the new letsencrypt-auto script. Over the past
couple months, we've been working on increasing the reliability and
security of letsencrypt-auto. A number of changes landed in this
release to prepare for the new version of this script.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.3.0

## 0.2.0 - 2016-01-14

### Added

* Added Apache plugin support for non-Debian based systems. Support has been
added for modern Red Hat based systems such as Fedora 23, Red Hat 7,
and CentOS 7 running Apache 2.4. In theory, this plugin should be
able to be configured to run on any Unix-like OS running Apache 2.4.
* Relaxed PyOpenSSL version requirements. This adds support for systems
with PyOpenSSL versions 0.13 or 0.14.
* Improved error messages from the client.

### Fixed

* Resolved issues with the Apache plugin enabling an HTTP to HTTPS
redirect on some systems.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.2.0

## 0.1.1 - 2015-12-15

### Added

* Added a check that avoids attempting to issue for unqualified domain names like
"localhost".

### Fixed

* Fixed a confusing UI path that caused some users to repeatedly renew
their certs while experimenting with the client, in some cases hitting
issuance rate limits.
* Fixed numerous Apache configuration parser problems
* Fixed --webroot permission handling for non-root users

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=milestone%3A0.1.1
