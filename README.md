# STARTTLS Everywhere


## Example usage

**WARNING: this is a pre-alpha codebase.  Do not run it on production
mailservers!!!**


If you have a Postfix server you're willing to endanger deliverability on, you
can try obtain a certificate with the [Let's Encrypt Python Client](https://github.com/letsencrypt/letsencrypt), note the directory it lives in below `/etc/letsencrypt/live` and then do:

```
git clone https://github.com/EFForg/starttls-everywhere
cd starttls-everywhere
# Promise you don't care if deliverability breaks on this mail server
letsencrypt-postfix/PostfixConfigGenerator.py examples/starttls-everywhere.json /etc/postfix /etc/letsencrypt/live/YOUR.DOMAIN.EXAMPLE.COM
```

This will:
* Ensure your mail server initiates STARTTLS encryption
* Install the Let's Encrypt cert in Postfix
* Enforce mandatory TLS to some major email domains
* Enforce minimum TLS versions to some major email domains

## Project status

STARTTLS Everywhere development is re-starting after a hiatus.  Initial
objectives:

* Postfix configuration generation: working pre-alpha, not yet safe
* Email security database: working pre-alpha, definitely not yet safe
* Fully integrated Let's Encrypt client postfix plugin: in progress, not yet ready
* DANE support: none yet
* DEEP support: none yet
* SMTP-STS integration: none yet
* Direct mechanisms for mail domains to request inclusion: none yet
* Failure reporting mechanisms: early progress, not yet ready
* Mechanisms for secure multi-organization signature on the policy database:
  none yet
* Support for mail servers other than Postfix: none yet

## Authors

Jacob Hoffman-Andrews <jsha@eff.org>,     
Peter Eckersley <pde@eff.org>,     
Daniel Wilcox <dmwilcox@gmail.com>,     
Aaron Zauner <azet@azet.org>

## Mailing List

starttls-everywhere@eff.org, https://lists.eff.org/mailman/listinfo/starttls-everywhere

## Background

Most email transferred between SMTP servers (aka MTAs) is transmitted in the clear and trivially interceptable. Encryption of SMTP traffic is possible using the STARTTLS mechanism, which encrypts traffic but is vulnerable to trivial downgrade attacks.

To illustrate an easy version of this attack, suppose a network-based attacker `Mallory` notices that `Alice` has just uploaded message to her mail server. `Mallory` can inject a TCP reset (RST) packet during the mail server's next TLS negotiation with another mail server. Nearly all mail servers that implement STARTTLS do so in opportunistic mode, which means that they will retry without encryption if there is any problem with a TLS connection. So `Alice`'s message will be transmitted in the clear.

Opportunistic TLS in SMTP also extends to certificate validation. Mail servers commonly provide self-signed certificates or certificates with non-validatable hostnames, and senders commonly accept these. This means that if we say 'require TLS for this mail domain,' the domain may still be vulnerable to a man-in-the-middle using any key and certificate chosen by the attacker.

Even if senders require a valid certificate that matches the hostname of a mail host, a DNS MITM or Denial of Service is still possible. The sender, to find the correct target hostname, queries DNS for MX records on the recipient domain. Absent DNSSEC, the response can be spoofed to provide the attacker's hostname, for which the attacker holds a valid certificate.

STARTTLS by itself thwarts purely passive eavesdroppers. However, as currently deployed, it allows either bulk or semi-targeted attacks that are very unlikely to be detected. We would like to deploy both detection and prevention for such semi-targeted attacks.

## Goals

*   Prevent RST attacks from revealing email contents in transit between major MTAs that support STARTTLS.
*   Prevent MITM attacks at the DNS, SMTP, TLS, or other layers from revealing same.
*   Zero or minimal decrease to deliverability rates unless network attacks are actually occurring.
*   Create feedback-loops on targeted attacks and bulk surveilance in an opt-in, anonymized way.

## Non-goals

*   Prevent fully-targeted exploits of vulnerabilities on endpoints or on mail hosts.
*   Refuse delivery on the recipient side if sender does not negotiate TLS (this may be a future project).
*   Develop a fully-decentralized solution.
*   Initially we are not engineering to scale to all mail domains on the Internet, though we believe this design can be scaled as required if large numbers of domains publish policies to it.

## Motivating examples

*   [Unnammed mobile broadband provider overwrites STARTTLS flag and commands to
    prevent negotiating an encrypted connection](https://www.techdirt.com/articles/20141012/06344928801/revealed-isps-already-violating-net-neutrality-to-block-encryption-make-everyone-less-safe-online.shtml)
*   [Unknown party removes STARTTLS flag from all SMTP connections leaving
    Thailand](http://www.telecomasia.net/content/google-yahoo-smtp-email-severs-hit-thailand)

## Threat model

Attacker has control of routers on the path between two MTAs of interest. Attacker cannot or will not issue valid certificates for arbitrary names. Attacker cannot or will not attack endpoints. We are trying to protect confidentiality and integrity of email transmitted over SMTP between MTAs.

## Alternatives

Our goals can also be accomplished through use of [DNSSEC and DANE](http://tools.ietf.org/html/draft-ietf-dane-smtp-with-dane-10), which is certainly a more scalable solution. However, operators have been very slow to roll out DNSSEC supprt. We feel there is value in deploying an intermediate solution that does not rely on DNSSEC. This will improve the email security situation more quickly. It will also provide operational experience with authenticated SMTP over TLS that will make eventual rollout of DANE-based solutions easier.

## Detailed design

Senders need to know which target hosts are known to support STARTTLS, and how to authenticate them. Since the network cannot be trusted to provide this information, it must be communicated securely out-of-band. We will provide:

  (a) a configuration file format to convey STARTTLS support for recipient domains,

  (b) Python code (config-generator) to transform (a) into configuration files for popular MTAs., and

  (c) a method to create and securely distribute files of type (a) for major email domains that that agree to be included, plus any other domains that proactively request to be included.

## File Format

The basic file format will be JSON with comments (http://blog.getify.com/json-comments/). Example:

    {
      // Canonical URL https://eff.org/starttls-everywhere/config -- redirects to latest version
      "timestamp": "2014-06-06T14:30:16+00:00",
      // "timestamp": 1401414363,  : also acceptable
      "author": "Electronic Frontier Foundation https://eff.org",
      "expires": "2014-06-06T14:30:16+00:00",
      "tls-policies": {
        // These match on the MX domain.
        "*.yahoodns.net": {
           "require-valid-certificate": true,
         }
        "*.eff.org": {
          "require-tls": true,
          "min-tls-version": "TLSv1.1",
          "enforce-mode": "enforce"
          "accept-spki-hashes": [
            "sha1/5R0zeLx7EWRxqw6HRlgCRxNLHDo=",
            "sha1/YlrkMlC6C4SJRZSVyRvnvoJ+8eM="
          ]
        }
        "*.google.com": {
          "require-valid-certificate": true,
          "min-tls-version": "TLSv1.1",
          "enforce-mode": "log-only",
          "error-notification": "https://google.com/post/reports/here"
        },
      }
      // Since the MX lookup is not secure, we list valid responses for each
      // address domain, to protect against DNS spoofing.
      "acceptable-mxs": {
        "yahoo.com": {
          "accept-mx-domains": ["*.yahoodns.net"]
        }
        "gmail.com": {
          "accept-mx-domains": ["*.google.com"]
        }
        "eff.org": {
          "accept-mx-domains": ["*.eff.org"]
        }
      }
    }


A user of this file format may choose to accept multiple files. For instance, the EFF might provide an overall configuration covering major mail providers, and another organization might produce an overlay for mail providers in a specific country. If so, they override each other on a per-domain basis.

The _timestamp_ field is an integer number of epoch seconds from 00:00:00 UTC on 1 January 1970. When retrieving a fresh configuration file, config-generator should validate that the timestamp is greater than or equal to the version number of the file it already has.

There is no inline signature field. The configuration file should be distributed with authentication using an offline signing key.

Option 1: Plain JSON distributed with a signature using gpg --clearsign. Config-generator should validate the signature against a known GPG public key before extracting. The public key is part of the permanent system configuration, like the fetch URL.

Option 2: Git is a revision control system built on top of an authenticated, history-preserving file system.  Let's use it as an authenticated, history preserving file system: valid versions of recipient policy files may be fetched and verified via signed git tags.  [Here's an example shell recipe to do this.](https://gist.github.com/jsha/6230206e89759cc6e00d)

Config-generator should attempt to fetch the configuration file daily and transform it into MTA configs. If there is a retrieval failure, and the cached configuration file has an 'expires' time past the current date, an alert should be raised to the system operator and all existing configs from config-generator should be removed, reverting the MTA configuration to use opportunistic TLS for all domains.

**address-domains**

The _address-domains_ field maps from mail domains (the part of an address after the "@") onto a list of properties for that domain. Matching of mail domains is on an exact-match basis, not a subdomain basis. For instance, eff.org would be listed separately from lists.eff.org in the _address-domains_ section.

Currently the only property defined for _address-domains_ is _accept-mx-domains_, a list. If an MX lookup for a listed address domain returns a hostname that is not a subdomain of one of the domains listed in the _accept-mx-domains_ property, the MTA should fail delivery or log an advisory failure, as appropriate. Matching of MX hostnames against the _accept-mx-domains_ list is on a subdomain basis. For instance, if an MX record for yahoo.com lists mta7.am0.yahoodns.net, and the _accept-mx-domains_ property for yahoo.com is ["yahoodns.net"], that should be considered a match. All domains listed in any _accept-mx-domains_ list must correspond to an exactly matching field in the _mx-domains_ config section.

The _accept-mx-domains_ mechanism partially solves the problem of DNS MITM. It doesn't completely solve the problem, since an attacker might somehow control a different hostname under an acceptable domain, e.g. evil.yahoodns.net. But it strikes a balance between improving security and allowing mail operators to change configuration as needed. Some mail operators delegate their MX handling to a third-party provider (i.e. Google Apps for Your Domain). If those operators are included in STARTTLS Everywhere and wish to change providers, they will have to first send an update to their _accept-mx-domains_ to include their new provider.

**mx-domains**

The keys of this section are MX domains as described above for the _accept-mx-domains_ property. Each _mx-domain_ entry must be an exact match with an entry in one of the _accept-mx-domains_ lists provided. No _mx-domain_can be a subdomain of any other _mx-domain_in the configuration file. Fields in this section specify minimum security requirements that should be applied when connecting to any MX hostname that is a subdomain of the specified _mx-domain_.

Implicitly each _mx-domain_ listed has a property _require-tls: true_. MX domains that do not support TLS will not be listed. The only required property is _enforce-mode_, which must be either _log-only_ or _enforce_. If _enforce-mode_ is _log-only_, the generated configs will not stop mail delivery on policy failures, but will produce logging information.

If the _min-tls-version_ property is present, sending mail to domains under this policy should fail if the sending MTA cannot negotiate a TLS version equal to or greater than the listed version. Valid values are _TLSv1, TLSv1.1, and TLSv1.2._

_Require-valid-certificate_defaults to false. If the _require-valid-certificate_ property is 'true' for a given _mx-domain_ the certificate presented must be valid for a hostname that is subdomain of the _mx-domain_. Validity means all of these must be true:

1.  The CN or a DNS entry under subjectAltName matches an appropriate hostname.
2.  The certificate is unexpired.
3.  There is a valid chain from the certificate to a root certificate included in [Mozilla's trust store](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/included/) (available as [Debian package ca-certificates](https://packages.debian.org/sid/ca-certificates)).

The _accept-pinset_ field references an entry in the pinsets list, which has the same format and semantics as [Chrome's pinning list](https://src.chromium.org/chrome/trunk/src/net/http/transport_security_state_static.json). Most _mx-domain_s should specify a pinset that describes trust roots rather than leaf certificates, but both are possible. Pinning will only be added at the request of mail operators because it requires operators be careful when issuing new leaf certificates.

## Pinning and hostname verification

Like Chrome and Firefox we want to encourage pinning to a trusted root or intermediate rather than a leaf cert, to minimize spurious pinning failures when hosts rotate keys.

The other option is to automatically pin leaf certs as observed in the wild.  This would be one solution to the hostname verification and self-signed certificate problem. However, it is a non-starter. Even if we expect mail operators to auto-update configuration on a daily basis, this approach cannot add new certs until they are observed in the wild. That means that any time an operator rotates keys on a mail server, there would be a significant window of time in which the new keys would be rejected.

We do not attempt to solve the self-signed certificate problem. For mail hosts with self-signed certificates, we can require TLS but will not require validation of the certificates. Such hosts should be encouraged to upgrade to a CA-signed certificate that can be validated by senders.

## Creating configuration

We have three options for creating the configuration file:

1.  Ask mail operators to submit policies for their domains which we incorporate.
2.  Manually curate a set of policies for the top `N` mail domains.
3.  Programmatically create a set of policies by connecting to the top N mail domains.

For option (1), there's a bootstrapping problem: No one will opt in until it's useful; It won't be useful until people opt in. Option (1) does have the advantage that it's the only good way to get pinning directives.

For option (3) we'd be likely to pull in bad policies that could result in failed delivery.

We'll initially launch a demo using option (2), do some initial deployments to prove viability and delivery rate impact, and then start reaching out to operators to do option (1).

## Distribution

The configuration file will be provided at a long-term maintained URL. It will be signed using a key held offline on an airgapped machine or smartcard.

Since recipient mail servers may abruptly stop supporting TLS, we will request that mail operators set up auto-updating of the configuration file, with signature verification. This allows us to minimize the delivery impact of such events. However, config-generator should not auto-update its own code, since that would amount to auto-deployment of third party code, which some operators may not wish to do.

We may choose to implement a form of immutable log along the lines of certificate transparency. This would be appealing if we chose to use this mechanism to distribute expected leaf keys as a primary authentication mechanism, but as described in "Pinning and hostname verification," that's not a viable option. Instead we will rely on the CA ecosystem to do primary authentication, so an immutable log for this system is probably overkill, engineering-wise.

## Python code

Config-generator should parse input JSON and produce output configs for various mail servers. It should not be possible for any input JSON to cause arbitrary code execution or even any MTA config directives beyond the ones that specifically impact the decision to deliver or bounce based on TLS support. For instance, it must not be possible for config-generator to output a directive to forward mail from one domain to another. Config-generator will have the option to directly pull the latest config from a URL, or from a file on local disk distributed regularly from another system that has outside network access.

Config-generator will be manually updated by mail operators.

## Testing

We will create a reproducible test configuration that can be run locally and exercises each of the major cases: Enforce mode vs log mode; Enforced TLS negotiation, enforced MX hostname match, and enforced valid certificates.

Additionally, for ongoing monitoring of third-party deployments, we will create a canary mail domain that intentionally fails one of the tests but is included in the configuration file. For instance, starttls-canary.org would be listed in the configuration as requiring STARTTLS, but would not actually offer STARTTLS. Each time a mail operator commits to configuring STARTTLS Everywhere, we would request an account on their email domain from which to send automated daily email to starttls-canary.org. We should expect bounces. If such mail is successfully delivered to starttls-canary.org, that would indicate a configuration failure on the sending host, and we would manually notify the operator.

## Failure reporting

For the mail operator deploying STARTTLS Everywhere, we will provide log analysis scripts that can be used out-of-the-box to monitor how many delivery failures or would-be failures are due to STARTTLS Everywhere policies. These would be designed to run in a cron job or small opt-in daemon and send notices only when STARTTLS Everywhere-related failures exceed a certain percentage for any given recipient domains. For very high-volume mail operators, it would likely be necessary to adapt the analysis scripts to their own logging and analysis infrastructure.

For recipient domains who are listed in the STARTTLS Everywhere configuration, we would provide a configuration field to specify an email address or HTTPS URL to which that sender domains could send failure information. This would provide a mechanism for recipient domains to identify problems with their TLS deployment and fix them. The reported information should not contain any personal information, including email addresses.  Example fields for failure reports: timestamps at minute granularity, target MX hostname, resolved MX IP address, failure type, certificate. Since failures are likely to come in batches, the error sending mechanism should batch them up and summarize as necessary to avoid flooding the recipient.
