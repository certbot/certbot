# Certbot change log

Certbot adheres to [Semantic Versioning](http://semver.org/).

## 0.24.0 - 2018-05-02

### Added

* certbot now has an enhance subcommand which allows you to configure security
  enhancements like HTTP to HTTPS redirects, OCSP stapling, and HSTS without
  reinstalling a certificate.
* certbot-dns-rfc2136 now allows the user to specify the port to use to reach
  the DNS server in its credentials file.
* acme now parses the wildcard field included in authorizations so it can be
  used by users of the library.

### Changed

* certbot-dns-route53 used to wait for each DNS update to propagate before
  sending the next one, but now it sends all updates before waiting which
  speeds up issuance for multiple domains dramatically.
* Certbot's official Docker images are now based on Alpine Linux 3.7 rather
  than 3.4 because 3.4 has reached its end-of-life.
* We've doubled the time Certbot will spend polling authorizations before
  timing out.
* The level of the message logged when Certbot is being used with
  non-standard paths warning that crontabs for renewal included in Certbot
  packages from OS package managers may not work has been reduced. This stops
  the message from being written to stderr every time `certbot renew` runs.

### Fixed

* certbot-auto now works with Python 3.6.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* acme
* certbot
* certbot-apache
* certbot-dns-digitalocean (only style improvements to tests)
* certbot-dns-rfc2136

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/52?closed=1

## 0.23.0 - 2018-04-04

### Added

* Support for OpenResty was added to the Nginx plugin.

### Changed

* The timestamps in Certbot's logfiles now use the system's local time zone
  rather than UTC.
* Certbot's DNS plugins that use Lexicon now rely on Lexicon>=2.2.1 to be able
  to create and delete multiple TXT records on a single domain.
* certbot-dns-google's test suite now works without an internet connection.

### Fixed

* Removed a small window that if during which an error occurred, Certbot
  wouldn't clean up performed challenges.
* The parameters `default` and `ipv6only` are now removed from `listen`
  directives when creating a new server block in the Nginx plugin.
* `server_name` directives enclosed in quotation marks in Nginx are now properly
  supported.
* Resolved an issue preventing the Apache plugin from starting Apache when it's
  not currently running on RHEL and Gentoo based systems.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* certbot
* certbot-apache
* certbot-dns-cloudxns
* certbot-dns-dnsimple
* certbot-dns-dnsmadeeasy
* certbot-dns-google
* certbot-dns-luadns
* certbot-dns-nsone
* certbot-dns-rfc2136
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/50?closed=1

## 0.22.2 - 2018-03-19

### Fixed

* A type error introduced in 0.22.1 that would occur during challenge cleanup
  when a Certbot plugin raises an exception while trying to complete the
  challenge was fixed.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* certbot

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/53?closed=1

## 0.22.1 - 2018-03-19

### Changed

* The ACME server used with Certbot's --dry-run and --staging flags is now
  Let's Encrypt's ACMEv2 staging server which allows people to also test ACMEv2
  features with these flags.

### Fixed

* The HTTP Content-Type header is now set to the correct value during
  certificate revocation with new versions of the ACME protocol.
* When using Certbot with Let's Encrypt's ACMEv2 server, it would add a blank
  line to the top of chain.pem and between the certificates in fullchain.pem
  for each lineage. These blank lines have been removed.
* Resolved a bug that caused Certbot's --allow-subset-of-names flag not to
  work.
* Fixed a regression in acme.client.Client that caused the class to not work
  when it was initialized without a ClientNetwork which is done by some of the
  other projects using our ACME library.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* acme
* certbot

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/51?closed=1

## 0.22.0 - 2018-03-07

### Added

* Support for obtaining wildcard certificates and a newer version of the ACME
  protocol such as the one implemented by Let's Encrypt's upcoming ACMEv2
  endpoint was added to Certbot and its ACME library. Certbot still works with
  older ACME versions and will automatically change the version of the protocol
  used based on the version the ACME CA implements.
* The Apache and Nginx plugins are now able to automatically install a wildcard
  certificate to multiple virtual hosts that you select from your server
  configuration.
* The `certbot install` command now accepts the `--cert-name` flag for
  selecting a certificate.
* `acme.client.BackwardsCompatibleClientV2` was added to Certbot's ACME library
  which automatically handles most of the differences between new and old ACME
  versions. `acme.client.ClientV2` is also available for people who only want
  to support one version of the protocol or want to handle the differences
  between versions themselves.
* certbot-auto now supports the flag --install-only which has the script
  install Certbot and its dependencies and exit without invoking Certbot.
* Support for issuing a single certificate for a wildcard and base domain was
  added to our Google Cloud DNS plugin. To do this, we now require your API
  credentials have additional permissions, however, your credentials will
  already have these permissions unless you defined a custom role with fewer
  permissions than the standard DNS administrator role provided by Google.
  These permissions are also only needed for the case described above so it
  will continue to work for existing users. For more information about the
  permissions changes, see the documentation in the plugin.

### Changed

* We have broken lockstep between our ACME library, Certbot, and its plugins.
  This means that the different components do not need to be the same version
  to work together like they did previously. This makes packaging easier
  because not every piece of Certbot needs to be repackaged to ship a change to
  a subset of its components.
* Support for Python 2.6 and Python 3.3 has been removed from ACME, Certbot,
  Certbot's plugins, and certbot-auto. If you are using certbot-auto on a RHEL
  6 based system, it will walk you through the process of installing Certbot
  with Python 3 and refuse to upgrade to a newer version of Certbot until you
  have done so.
* Certbot's components now work with older versions of setuptools to simplify
  packaging for EPEL 7.

### Fixed

* Issues caused by Certbot's Nginx plugin adding multiple ipv6only directives
  has been resolved.
* A problem where Certbot's Apache plugin would add redundant include
  directives for the TLS configuration managed by Certbot has been fixed.
* Certbot's webroot plugin now properly deletes any directories it creates.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/48?closed=1

## 0.21.1 - 2018-01-25

### Fixed

* When creating an HTTP to HTTPS redirect in Nginx, we now ensure the Host
  header of the request is set to an expected value before redirecting users to
  the domain found in the header. The previous way Certbot configured Nginx
  redirects was a potential security issue which you can read more about at
  https://community.letsencrypt.org/t/security-issue-with-redirects-added-by-certbots-nginx-plugin/51493.
* Fixed a problem where Certbot's Apache plugin could fail HTTP-01 challenges
  if basic authentication is configured for the domain you request a
  certificate for.
* certbot-auto --no-bootstrap now properly tries to use Python 3.4 on RHEL 6
  based systems rather than Python 2.6.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/49?closed=1

## 0.21.0 - 2018-01-17

### Added

* Support for the HTTP-01 challenge type was added to our Apache and Nginx
  plugins. For those not aware, Let's Encrypt disabled the TLS-SNI-01 challenge
  type which was what was previously being used by our Apache and Nginx plugins
  last week due to a security issue. For more information about Let's Encrypt's
  change, click
  [here](https://community.letsencrypt.org/t/2018-01-11-update-regarding-acme-tls-sni-and-shared-hosting-infrastructure/50188).
  Our Apache and Nginx plugins will automatically switch to use HTTP-01 so no
  changes need to be made to your Certbot configuration, however, you should
  make sure your server is accessible on port 80 and isn't behind an external
  proxy doing things like redirecting all traffic from HTTP to HTTPS. HTTP to
  HTTPS redirects inside Apache and Nginx are fine.
* IPv6 support was added to the Nginx plugin.
* Support for automatically creating server blocks based on the default server
  block was added to the Nginx plugin.
* The flags --delete-after-revoke and --no-delete-after-revoke were added
  allowing users to control whether the revoke subcommand also deletes the
  certificates it is revoking.

### Changed

* We deprecated support for Python 2.6 and Python 3.3 in Certbot and its ACME
  library. Support for these versions of Python will be removed in the next
  major release of Certbot. If you are using certbot-auto on a RHEL 6 based
  system, it will guide you through the process of installing Python 3.
* We split our implementation of JOSE (Javascript Object Signing and
  Encryption) out of our ACME library and into a separate package named josepy.
  This package is available on [PyPI](https://pypi.python.org/pypi/josepy) and
  on [GitHub](https://github.com/certbot/josepy).
* We updated the ciphersuites used in Apache to the new [values recommended by
  Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29).
  The major change here is adding ChaCha20 to the list of supported
  ciphersuites.

### Fixed

* An issue with our Apache plugin on Gentoo due to differences in their
  apache2ctl command have been resolved.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/47?closed=1

## 0.20.0 - 2017-12-06

### Added

* Certbot's ACME library now recognizes URL fields in challenge objects in
  preparation for Let's Encrypt's new ACME endpoint. The value is still
  accessible in our ACME library through the name "uri".

### Changed

* The Apache plugin now parses some distro specific Apache configuration files
  on non-Debian systems allowing it to get a clearer picture on the running
  configuration. Internally, these changes were structured so that external
  contributors can easily write patches to make the plugin work in new Apache
  configurations.
* Certbot better reports network failures by removing information about
  connection retries from the error output.
* An unnecessary question when using Certbot's webroot plugin interactively has
  been removed.

### Fixed

* Certbot's NGINX plugin no longer sometimes incorrectly reports that it was
  unable to deploy a HTTP->HTTPS redirect when requesting Certbot to enable a
  redirect for multiple domains.
* Problems where the Apache plugin was failing to find directives and
  duplicating existing directives on openSUSE have been resolved.
* An issue running the test shipped with Certbot and some our DNS plugins with
  older versions of mock have been resolved.
* On some systems, users reported strangely interleaved output depending on
  when stdout and stderr were flushed. This problem was resolved by having
  Certbot regularly flush these streams.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/44?closed=1

## 0.19.0 - 2017-10-04

### Added

* Certbot now has renewal hook directories where executable files can be placed
  for Certbot to run with the renew subcommand. Pre-hooks, deploy-hooks, and
  post-hooks can be specified in the renewal-hooks/pre, renewal-hooks/deploy,
  and renewal-hooks/post directories respectively in Certbot's configuration
  directory (which is /etc/letsencrypt by default). Certbot will automatically
  create these directories when it is run if they do not already exist.
* After revoking a certificate with the revoke subcommand, Certbot will offer
  to delete the lineage associated with the certificate. When Certbot is run
  with --non-interactive, it will automatically try to delete the associated
  lineage.
* When using Certbot's Google Cloud DNS plugin on Google Compute Engine, you no
  longer have to provide a credential file to Certbot if you have configured
  sufficient permissions for the instance which Certbot can automatically
  obtain using Google's metadata service.

### Changed

* When deleting certificates interactively using the delete subcommand, Certbot
  will now allow you to select multiple lineages to be deleted at once.
* Certbot's Apache plugin no longer always parses Apache's sites-available on
  Debian based systems and instead only parses virtual hosts included in your
  Apache configuration. You can provide an additional directory for Certbot to
  parse using the command line flag --apache-vhost-root.

### Fixed

* The plugins subcommand can now be run without root access.
* certbot-auto now includes a timeout when updating itself so it no longer
  hangs indefinitely when it is unable to connect to the external server.
* An issue where Certbot's Apache plugin would sometimes fail to deploy a
  certificate on Debian based systems if mod_ssl wasn't already enabled has
  been resolved.
* A bug in our Docker image where the certificates subcommand could not report
  if certificates maintained by Certbot had been revoked has been fixed.
* Certbot's RFC 2136 DNS plugin (for use with software like BIND) now properly
  performs DNS challenges when the domain being verified contains a CNAME
  record.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/43?closed=1

## 0.18.2 - 2017-09-20

### Fixed

* An issue where Certbot's ACME module would raise an AttributeError trying to
  create self-signed certificates when used with pyOpenSSL 17.3.0 has been
  resolved. For Certbot users with this version of pyOpenSSL, this caused
  Certbot to crash when performing a TLS SNI challenge or when the Nginx plugin
  tried to create an SSL server block.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/46?closed=1

## 0.18.1 - 2017-09-08

### Fixed

* If certbot-auto was running as an unprivileged user and it upgraded from
  0.17.0 to 0.18.0, it would crash with a permissions error and would need to
  be run again to successfully complete the upgrade. This has been fixed and
  certbot-auto should upgrade cleanly to 0.18.1.
* Certbot usually uses "certbot-auto" or "letsencrypt-auto" in error messages
  and the User-Agent string instead of "certbot" when you are using one of
  these wrapper scripts. Proper detection of this was broken with Certbot's new
  installation path in /opt in 0.18.0 but this problem has been resolved.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/45?closed=1

## 0.18.0 - 2017-09-06

### Added

* The Nginx plugin now configures Nginx to use 2048-bit Diffie-Hellman
  parameters. Java 6 clients do not support Diffie-Hellman parameters larger
  than 1024 bits, so if you need to support these clients you will need to
  manually modify your Nginx configuration after using the Nginx installer.

### Changed

* certbot-auto now installs Certbot in directories under `/opt/eff.org`. If you
  had an existing installation from certbot-auto, a symlink is created to the
  new directory. You can configure certbot-auto to use a different path by
  setting the environment variable VENV_PATH.
* The Nginx plugin can now be selected in Certbot's interactive output.
* Output verbosity of renewal failures when running with `--quiet` has been
  reduced.
* The default revocation reason shown in Certbot help output now is a human
  readable string instead of a numerical code.
* Plugin selection is now included in normal terminal output.

### Fixed

* A newer version of ConfigArgParse is now installed when using certbot-auto
  causing values set to false in a Certbot INI configuration file to be handled
  intuitively. Setting a boolean command line flag to false is equivalent to
  not including it in the configuration file at all.
* New naming conventions preventing certbot-auto from installing OS
  dependencies on Fedora 26 have been resolved.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/42?closed=1

## 0.17.0 - 2017-08-02

### Added

* Support in our nginx plugin for modifying SSL server blocks that do
  not contain certificate or key directives.
* A `--max-log-backups` flag to allow users to configure or even completely
  disable Certbot's built in log rotation.
* A `--user-agent-comment` flag to allow people who build tools around Certbot
  to differentiate their user agent string by adding a comment to its default
  value.

### Changed

* Due to some awesome work by
  [cryptography project](https://github.com/pyca/cryptography), compilation can
  now be avoided on most systems when using certbot-auto. This eliminates many
  problems people have had in the past such as running out of memory, having
  invalid headers/libraries, and changes to the OS packages on their system
  after compilation breaking Certbot.
* The `--renew-hook` flag has been hidden in favor of `--deploy-hook`. This new
  flag works exactly the same way except it is always run when a certificate is
  issued rather than just when it is renewed.
* We have started printing deprecation warnings in certbot-auto for
  experimentally supported systems with OS packages available.
* A certificate lineage's name is included in error messages during renewal.

### Fixed

* Encoding errors that could occur when parsing error messages from the ACME
  server containing Unicode have been resolved.
* certbot-auto no longer prints misleading messages about there being a newer
  pip version available when installation fails.
* Certbot's ACME library now properly extracts domains from critical SAN
  extensions.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.17.0+is%3Aclosed

## 0.16.0 - 2017-07-05

### Added

* A plugin for performing DNS challenges using dynamic DNS updates as defined
  in RFC 2316. This plugin is packaged separately from Certbot and is available
  at https://pypi.python.org/pypi/certbot-dns-rfc2136. It supports Python 2.6,
  2.7, and 3.3+. At this time, there isn't a good way to install this plugin
  when using certbot-auto, but this should change in the near future.
* Plugins for performing DNS challenges for the providers
  [DNS Made Easy](https://pypi.python.org/pypi/certbot-dns-dnsmadeeasy) and
  [LuaDNS](https://pypi.python.org/pypi/certbot-dns-luadns). These plugins are
  packaged separately from Certbot and support Python 2.7 and 3.3+. Currently,
  there isn't a good way to install these plugins when using certbot-auto,
  but that should change soon.
* Support for performing TLS-SNI-01 challenges when using the manual plugin.
* Automatic detection of Arch Linux in the Apache plugin providing better
  default settings for the plugin.

### Changed

* The text of the interactive question about whether a redirect from HTTP to
  HTTPS should be added by Certbot has been rewritten to better explain the
  choices to the user.
* Simplified HTTP challenge instructions in the manual plugin.

### Fixed

* Problems performing a dry run when using the Nginx plugin have been fixed.
* Resolved an issue where certbot-dns-digitalocean's test suite would sometimes
  fail when ran using Python 3.
* On some systems, previous versions of certbot-auto would error out with a
  message about a missing hash for setuptools. This has been fixed.
* A bug where Certbot would sometimes not print a space at the end of an
  interactive prompt has been resolved.
* Nonfatal tracebacks are no longer shown in rare cases where Certbot
  encounters an exception trying to close its TCP connection with the ACME
  server.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.16.0+is%3Aclosed

## 0.15.0 - 2017-06-08

### Added

* Plugins for performing DNS challenges for popular providers. Like the Apache
  and Nginx plugins, these plugins are packaged separately and not included in
  Certbot by default. So far, we have plugins for
  [Amazon Route 53](https://pypi.python.org/pypi/certbot-dns-route53),
  [Cloudflare](https://pypi.python.org/pypi/certbot-dns-cloudflare),
  [DigitalOcean](https://pypi.python.org/pypi/certbot-dns-digitalocean), and
  [Google Cloud](https://pypi.python.org/pypi/certbot-dns-google) which all
  work on Python 2.6, 2.7, and 3.3+. Additionally, we have plugins for
  [CloudXNS](https://pypi.python.org/pypi/certbot-dns-cloudxns),
  [DNSimple](https://pypi.python.org/pypi/certbot-dns-dnsimple),
  [NS1](https://pypi.python.org/pypi/certbot-dns-nsone) which work on Python
  2.7 and 3.3+ (and not 2.6). Currently, there isn't a good way to install
  these plugins when using `certbot-auto`, but that should change soon.
* IPv6 support in the standalone plugin. When performing a challenge, the
  standalone plugin automatically handles listening for IPv4/IPv6 traffic based
  on the configuration of your system.
* A mechanism for keeping your Apache and Nginx SSL/TLS configuration up to
  date. When the Apache or Nginx plugins are used, they place SSL/TLS
  configuration options in the root of Certbot's config directory
  (`/etc/letsencrypt` by default). Now when a new version of these plugins run
  on your system, they will automatically update the file to the newest
  version if it is unmodified. If you manually modified the file, Certbot will
  display a warning giving you a path to the updated file which you can use as
  a reference to manually update your modified copy.
* `--http-01-address` and `--tls-sni-01-address` flags for controlling the
  address Certbot listens on when using the standalone plugin.
* The command `certbot certificates` that lists certificates managed by Certbot
  now performs additional validity checks to notify you if your files have
  become corrupted.

### Changed

* Messages custom hooks print to `stdout` are now displayed by Certbot when not
  running in `--quiet` mode.
* `jwk` and `alg` fields in JWS objects have been moved into the protected
  header causing Certbot to more closely follow the latest version of the ACME
  spec.

### Fixed

* Permissions on renewal configuration files are now properly preserved when
  they are updated.
* A bug causing Certbot to display strange defaults in its help output when
  using Python <= 2.7.4 has been fixed.
* Certbot now properly handles mixed case domain names found in custom CSRs.
* A number of poorly worded prompts and error messages.

### Removed

* Support for OpenSSL 1.0.0 in `certbot-auto` has been removed as we now pin a
  newer version of `cryptography` which dropped support for this version.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.15.0+is%3Aclosed

## 0.14.2 - 2017-05-25

### Fixed

* Certbot 0.14.0 included a bug where Certbot would create a temporary log file
(usually in /tmp) if the program exited during argument parsing. If a user
provided -h/--help/help, --version, or an invalid command line argument,
Certbot would create this temporary log file. This was especially bothersome to
certbot-auto users as certbot-auto runs `certbot --version` internally to see
if the script needs to upgrade causing it to create at least one of these files
on every run. This problem has been resolved.

More details about this change can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.14.2+is%3Aclosed

## 0.14.1 - 2017-05-16

### Fixed

* Certbot now works with configargparse 0.12.0.
* Issues with the Apache plugin and Augeas 1.7+ have been resolved.
* A problem where the Nginx plugin would fail to install certificates on
systems that had the plugin's SSL/TLS options file from 7+ months ago has been
fixed.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.14.1+is%3Aclosed

## 0.14.0 - 2017-05-04

### Added

* Python 3.3+ support for all Certbot packages. `certbot-auto` still currently
only supports Python 2, but the `acme`, `certbot`, `certbot-apache`, and
`certbot-nginx` packages on PyPI now fully support Python 2.6, 2.7, and 3.3+.
* Certbot's Apache plugin now handles multiple virtual hosts per file.
* Lockfiles to prevent multiple versions of Certbot running simultaneously.

### Changed

* When converting an HTTP virtual host to HTTPS in Apache, Certbot only copies
the virtual host rather than the entire contents of the file it's contained
in.
* The Nginx plugin now includes SSL/TLS directives in a separate file located
in Certbot's configuration directory rather than copying the contents of the
file into every modified `server` block.

### Fixed

* Ensure logging is configured before parts of Certbot attempt to log any
messages.
* Support for the `--quiet` flag in `certbot-auto`.
* Reverted a change made in a previous release to make the `acme` and `certbot`
packages always depend on `argparse`. This dependency is conditional again on
the user's Python version.
* Small bugs in the Nginx plugin such as properly handling empty `server`
blocks and setting `server_names_hash_bucket_size` during challenges.

As always, a more complete list of changes can be found on GitHub:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.14.0+is%3Aclosed

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
