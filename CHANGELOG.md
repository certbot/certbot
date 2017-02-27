# 0.11.1
## 02/01/2017

* Resolve a problem where Certbot would crash while parsing command line
arguments in some cases.
* Fix a typo.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/pulls?q=is%3Apr%20milestone%3A0.11.1%20is%3Aclosed

# 0.11.0
## 02/01/2017

* Providing `--quiet` to `certbot-auto` now silences package manager output.
* The UI has been improved in the standalone plugin. When using the
plugin while running Certbot interactively and a required port is bound
by another process, Certbot will give you the option to retry to grab
the port rather than immediately exiting.
* You are now able to deactivate your account with the Let's Encrypt
server using the `unregister` subcommand.
* When revoking a certificate using the `revoke` subcommand, you now
have the option to provide the reason the certificate is being revoked
to Let's Encrypt with `--reason`.
* Removal of the optional `dnspython` dependency in our `acme` package.
Now the library does not support client side verification of the DNS
challenge.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.11.0+is%3Aclosed

# 0.10.2
## 01/25/2017

* We now save `--preferred-challenges` values for renewal. Previously 
these values were discarded causing a different challenge type to be 
used when renewing certs in some cases. 
* If Certbot receives a request with a `badNonce` error, we 
automatically retry the request. Since nonces from Let's Encrypt expire, 
this helps people performing the DNS challenge with the `manual` plugin 
who may have to wait an extended period of time for their DNS changes to 
propagate. 

More details about these changes can be found on our GitHub repo: 
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.2+is%3Aclosed 

# 0.10.1
## 01/13/2017

* Resolve problems where when asking Certbot to update a certificate at 
an existing path to include different domain names, the old names would 
continue to be used. 
* Fix issues successfully running our unit test suite on some systems. 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.1+is%3Aclosed 

# 0.10.0
## 01/11/2017

* The ability to customize and automatically complete DNS and HTTP 
domain validation challenges with the manual plugin. The flags 
`--manual-auth-hook` and `--manual-cleanup-hook` can now be provided 
when using the manual plugin to execute commands provided by the user to 
perform and clean up challenges provided by the CA. This is best used in 
complicated setups where the DNS challenge must be used or Certbot's 
existing plugins cannot be used to perform HTTP challenges. For more 
information on how this works, see `certbot --help manual`. 
* A `--cert-name` flag for specifying the name to use for the 
certificate in Certbot's configuration directory. Using this flag in 
combination with `-d/--domains`, a user can easily request a new 
certificate with different domains and save it with the name provided by 
`--cert-name`. Additionally, `--cert-name` can be used to select a 
certificate with the `certonly` and `run` subcommands so a full list of 
domains in the certificate does not have to be provided. 
* The subcommand `certificates` for listing the certificates managed by 
Certbot and their properties. 
* A `delete` subcommand for removing certificates managed by Certbot 
from the configuration directory. 
* Support for requesting internationalized domain names (IDNs). 
* Removal of the ncurses interface. This change solves problems people 
were having on many systems, reduces the number of Certbot dependencies, 
and simplifies our code. Certbot's only interface now is the text 
interface which was available by providing `-t/--text` to earlier 
versions of Certbot. 
* Hooks provided to Certbot are now saved to be reused during renewal. 
If you run Certbot with `--pre-hook`, `--renew-hook`, or `--post-hook` 
flags when obtaining a certificate, the provided commands will 
automatically be saved and executed again when renewing the certificate. 
A pre-hook and/or post-hook can also be given to the `certbot renew` 
command either on the command line or in a [configuration 
file](https://certbot.eff.org/docs/using.html#configuration-file) to run 
an additional command before/after any certificate is renewed. Hooks 
will only be run if a certificate is renewed. 
* Recategorized `-h/--help` output to improve documentation and 
discoverability. 
* Busybox support in certbot-auto. 
* Many small bug fixes. 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.0is%3Aclosed

# 0.9.3
## 10/13/2016

* Adopt more conservative behavior about reporting a needed port as 
unavailable when using the standalone plugin. 
* The Apache plugin uses information about your OS to help determine the 
layout of your Apache configuration directory. We added a patch to 
ensure this code behaves the same way when testing on different systems 
as the tests were failing in some cases. 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/27?closed=1 

# 0.9.2
## 10/12/2016

* Ensuring we properly copy `ssl on;` directives as necessary when 
performing domain validation in the Nginx plugin. 
* Verifying that our optional dependencies version matches what is 
required by Certbot. 
* A fix for problems where symlinks were becoming files when they were 
packaged, causing errors during testing and OS packaging. 
* Stop requiring that all possibly required ports are available when 
using the standalone plugin. Only verify the ports are available when 
you know they are necessary. 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/26?closed=1 

# 0.9.1
## 10/06/2016

* This version of Certbot simply fixes a bug that was introduced in version
0.9.0 where the command line flag -q/--quiet wasn't respected in some cases.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/25?closed=1 

# 0.9.0
## 10/05/2016

* An alpha version of the Nginx plugin. This plugin fully automates the 
process of obtaining and installing certificates with Nginx. 
Additionally, it is able to automatically configure security 
enhancements such as an HTTP to HTTPS redirect and OCSP stapling. To use 
this plugin, you must have the `certbot-nginx` package installed (which 
is installed automatically when using `certbot-auto`) and provide 
`--nginx` on the command line. This plugin is still in its early stages 
so we recommend you use it with some caution and make sure you have a 
backup of your Nginx configuration. 
* Support for the `DNS` challenge in the `acme` library as well as `DNS` 
support in Certbot's `manual` plugin. This allows you to create DNS 
records to prove to Let's Encrypt you control the requested the domain 
name. To use this feature, include `--manual --preferred-challenges dns` 
on the command line. 
* Help with enabling Extra Packages for Enterprise Linux (EPEL) on 
CentOS 6 when using `certbot-auto`. To use `certbot-auto` on CentOS 6, 
the EPEL repository has to be enabled. `certbot-auto` will now prompt 
users asking them if they would like the script to enable this for them 
automatically. This is done without prompting users when using 
`letsencrypt-auto` or if `-n/--non-interactive/--noninteractive` is 
included on the command line. 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.9.0+is%3Aclosed 

# 0.8.1
## 06/14/2016

* Preserving a certificate's common name when using `renew` 
* Save webroot values for renewal when they are entered interactively 
* Problems with an invalid user-agent string on OS X 
* Gracefully reporting the Apache plugin isn't usable when Augeas is not installed 
* Experimental support for Mageia has been added to `certbot-auto`

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.8.1+

# 0.8.0
## 06/02/2016

* The main new feature in this release is the `register` subcommand which 
can be used to register an account with the Let's Encrypt CA. 
* Additionally, you can run `certbot register --update-registration` to 
change the e-mail address associated with your registration. 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.8.0+

# 0.7.0
## 05/27/2016

* `--must-staple` to request certificates from Let's Encrypt with the 
OCSP must staple extension 
* automatic configuration of OSCP stapling for Apache 
* requesting certificates for domains found in the common name of a 
custom CSR 
* a number of bug fixes 

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=milestone%3A0.7.0+is%3Aissue 

# 0.6.0
## 05/12/2016 

* Renamed the client from `letsencrypt` to `certbot`
* Fixed a small json deserialization error
* Versioned the datetime dependency in setup.py
* Preserve domain order in generated CSRs
* Some minor bug fixes

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.6.0%20is%3Aclosed%20

# 0.5.0
## 04/05/2016

* The ability to use the webroot plugin interactively. 
* The flags --pre-hook, --post-hook, and --renew-hook which can be used 
with the renew subcommand to register shell commands to run in 
response to renewal events. Pre-hook commands will be run before 
any certs are renewed, post-hook commands will be run after any 
certs are renewed, and renew-hook commands will be run after each 
cert is renewed. If no certs are due for renewal, no command is run. 
* Cleaner renewal configuration files. In /etc/letsencrypt/renewal by 
default, these files can be used to control what parameters are used 
when renewing a specific certificate. 
* A -q/--quiet flag which silences all output except errors. 
* An --allow-subset-of-domains flag which can be used with the renew 
command to prevent renewal failures for a subset of the requested 
domains from causing the client to exit. 

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=milestone%3A0.5.0+is%3Aissue 

# 0.4.2
## 03/03/2016

* Resolves problems encountered when compiling letsencrypt 
against the new OpenSSL release. 
* A patch fixing problems of using letsencrypt renew with configuration files
from private beta has been added. 

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.4.2 

# 0.4.1
## 02/29/2016

* Fixes Apache parsing errors with some configurations
* Fixes Werkzeug dependency problems on some Red Hat systems
* Fixes bootstraping failures when using letsencrypt-auto with --no-self-upgrade
* Fixes problems with parsing renewal config files from private beta

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is:issue+milestone:0.4.1 

# 0.4.0
## 02/10/2016

* The new verb/subcommand `renew` can be used to renew your existing 
certificates as they approach expiration. Running `letsencrypt renew` 
will examine all existing certificate lineages and determine if any are 
less than 30 days from expiration. If so, the client will use the 
settings provided when you previously obtained the certificate to renew 
it. The subcommand finishes by printing a summary of which renewals were 
successful, failed, or not yet due. 
* A `--dry-run` flag has been added to help with testing configuration 
without affecting production rate limits. Currently supported by the 
`renew` and `certonly` subcommands, providing `--dry-run` on the command 
line will obtain certificates from the staging server without saving the 
resulting certificates to disk. 
* Major improvements have been added to letsencrypt-auto. This script 
has been rewritten to include full support for Python 2.6, the ability 
for letsencrypt-auto to update itself, and improvements to the 
stability, security, and performance of the script. 
* Support for Apache 2.2 has been added to the Apache plugin. 

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.4.0 
 
# 0.3.0
## 01/27/2016

* A non-interactive mode which can be enabled by including `-n` or 
`--non-interactive` on the command line. This can be used to 
guarantee the client will not prompt when run automatically using 
cron/systemd. 
* Preparation for the new letsencrypt-auto script. Over the past 
couple months, we've been working on increasing the reliability and 
security of letsencrypt-auto. A number of changes landed in this 
release to prepare for the new version of this script. 

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.3.0 

# 0.2.0
## 01/14/2016

* Apache plugin support for non-Debian based systems. Support has been 
added for modern Red Hat based systems such as Fedora 23, Red Hat 7, 
and CentOS 7 running Apache 2.4. In theory, this plugin should be 
able to be configured to run on any Unix-like OS running Apache 2.4. 
* Relaxed PyOpenSSL version requirements. This adds support for systems 
with PyOpenSSL versions 0.13 or 0.14. 
* Resolves issues with the Apache plugin enabling an HTTP to HTTPS 
redirect on some systems. 
* Improved error messages from the client. 

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.2.0 

# 0.1.1
## 12/15/2015

* Fix a confusing UI path that caused some users to repeatedly renew 
their certs while experimenting with the client, in some cases 
hitting issuance rate limits 
* Fixes numerous Apache configuration parser fixes 
* Avoids attempting to issue for unqualified domain names like 
"localhost" 
* Fixes --webroot permission handling for non-root users 

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=milestone%3A0.1.1 
