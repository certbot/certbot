============
Ciphersuites
============

.. contents:: Table of Contents
   :local:


.. _ciphersuites:

Introduction
============

Autoupdates
-----------

Within certain limits, TLS server software can choose what kind of
cryptography to use when a client connects. These choices can affect
security, compatibility, and performance in complex ways. Most of
these options are independent of a particular certificate. The Let's
Encrypt client tries to provide defaults that we think are most useful
to our users.

As described below, the Let's Encrypt client will default to modifying
server software's cryptographic settings to keep these up-to-date with
what we think are appropriate defaults when new versions of the Let's
Encrypt client are installed (for example, by an operating system package
manager).

When this feature is implemented, this document will be updated
to describe how to disable these automatic changes.


Cryptographic choices
---------------------

Software that uses cryptography must inevitably make choices about what
kind of cryptography to use and how. These choices entail assumptions
about how well particular cryptographic mechanisms resist attack, and what
trade-offs are available and appropriate. The choices are constrained
by compatibility issues (in order to interoperate with other software,
an implementation must agree to use cryptographic mechanisms that the
other side also supports) and protocol issues (cryptographic mechanisms
must be specified in protocols and there must be a way to agree to use
them in a particular context).

The best choices for a particular application may change over time in
response to new research, new standardization events, changes in computer
hardware, and changes in the prevalence of legacy software. Much important
research on cryptanalysis and cryptographic vulnerabilities is unpublished
because many researchers have been working in the interest of improving
some entities' communications security while weakening, or failing to
improve, others' security. But important information that improves our
understanding of the state of the art is published regularly.

When enabling TLS support in a compatible web server (which is a separate
step from obtaining a certificate), Let's Encrypt has the ability to
update that web server's TLS configuration. Again, this is *different
from the cryptographic particulars of the certificate itself*; the
certificate as of the initial release will be RSA-signed using one of
Let's Encrypt's 2048-bit RSA keys, and will describe the subscriber's
RSA public key ("subject public key") of at least 2048 bits, which is
used for key establishment.

Note that the subscriber's RSA public key can be used in a wide variety
of key establishment methods, most of which do not use RSA directly
for key exchange, but only for authenticating the server!  For example,
in DHE and ECDHE key exchanges, the subject public key is just used to
sign other parameters for authentication. You do not have to "use RSA"
for other purposes just because you're using an RSA key for authentication.

The certificate doesn't specify other cryptographic or ciphersuite
particulars; for example, it doesn't say whether or not parties should
use a particular symmetric algorithm like 3DES, or what cipher modes
they should use. All of these details are negotiated between client
and server independent of the content of the ciphersuite. The
Let's Encrypt project hopes to provide useful defaults that reflect
good security choices with respect to the publicly-known state of the
art. However, the Let's Encrypt certificate authority does *not*
dictate end-users' security policy, and any site is welcome to change
its preferences in accordance with its own policy or its administrators'
preferences, and use different cryptographic mechanisms or parameters,
or a different priority order, than the defaults provided by the Let's
Encrypt client.

If you don't use the Let's Encrypt client to configure your server
directly, because the client doesn't integrate with your server software
or because you chose not to use this integration, then the cryptographic
defaults haven't been modified, and the cryptography chosen by the server
will still be whatever the default for your software was.  For example,
if you obtain a certificate using *standalone* mode and then manually
install it in an IMAP or LDAP server, your cryptographic settings will
not be modified by the client in any way.


Sources of defaults
-------------------

Initially, the Let's Encrypt client will configure users' servers to
use the cryptographic defaults recommended by the Mozilla project.
These settings are well-reasoned recommendations that carefully
consider client software compatibility. They are described at

https://wiki.mozilla.org/Security/Server_Side_TLS

and the version implemented by the Let's Encrypt client will be the
version that was most current as of the release date of each client
version. Mozilla offers three separate sets of cryptographic options,
which trade off security and compatibility differently. These are
referred to as the "Modern", "Intermediate", and "Old" configurations
(in order from most secure to least secure, and least-backwards compatible
to most-backwards compatible). The client will follow the Mozilla defaults
for the *Intermediate* configuration by default, at least with regards to
ciphersuites and TLS versions. Mozilla's web site describes which client
software will be compatible with each configuration. You can also use
the Qualys SSL Labs site, which the Let's Encrypt software will suggest
when installing a certificate, to test your server and see whether it
will be compatible with particular software versions.

It will be possible to ask the Let's Encrypt client to instead apply
(and track) Modern or Old configurations.

The Let's Encrypt project expects to follow the Mozilla recommendations
in the future as those recommendations are updated. (For example, some
users have proposed prioritizing a new ciphersuite known as ``0xcc13``
which uses the ChaCha and Poly1305 algorithms, and which is already
implemented by the Chrome browser.  Mozilla has delayed recommending
``0xcc13`` over compatibility and standardization concerns, but is likely
to recommend it in the future once these concerns have been addressed. At
that point, the Let's Encrypt client would likely follow the Mozilla
recommendations and favor the use of this ciphersuite as well.)

The Let's Encrypt project may deviate from the Mozilla recommendations
in the future if good cause is shown and we believe our users'
priorities would be well-served by doing so. In general, please address
relevant proposals for changing priorities to the Mozilla security
team first, before asking the Let's Encrypt project to change the
client's priorities. The Mozilla security team is likely to have more
resources and expertise to bring to bear on evaluating reasons why its
recommendations should be updated.

The Let's Encrpyt project will entertain proposals to create a *very*
small number of alternative configurations (apart from Modern,
Intermediate, and Old) that there's reason to believe would be widely
used by sysadmins; this would usually be a preferable course to modifying
an existing configuration. For example, if many sysadmins want their
servers configured to track a different expert recommendation, Let's
Encrypt could add an option to do so.


Resources for recommendations
-----------------------------

In the course of considering how to handle this issue, we received
recommendations with sources of expert guidance on ciphersuites and other
cryptographic parameters. We're grateful to everyone who contributed
suggestions. The recommendations we received are available at

https://github.com/letsencrypt/letsencrypt/wiki/Ciphersuite-guidance

Let's Encrypt client users are welcome to review these authorities to
better inform their own cryptographic parameter choices. We also
welcome suggestions of other resources to add to this list. Please keep
in mind that different recommendations may reflect different priorities
or evaluations of trade-offs, especially related to compatibility!


Changing your settings
----------------------

This will probably look something like

.. code-block:: shell

  letsencrypt --cipher-recommendations mozilla-secure
  letsencrypt --cipher-recommendations mozilla-intermediate
  letsencrypt --cipher-recommendations mozilla-old

to track Mozilla's *Secure*, *Intermediate*, or *Old* recommendations,
and

.. code-block:: shell

  letsencrypt --update-ciphers on

to enable updating ciphers with each new Let's Encrypt client release,
or

.. code-block:: shell

  letsencrypt --update-ciphers off

to disable automatic configuration updates. These features have not yet
been implemented and this syntax may change then they are implemented.


TODO
----

The status of this feature is tracked as part of issue #1123 in our
bug tracker.

https://github.com/letsencrypt/letsencrypt/issues/1123

Prior to implementation of #1123, the client does not actually modify
ciphersuites (this is intended to be implemented as a "configuration
enhancement", but the only configuration enhancement implemented
so far is redirecting HTTP requests to HTTPS in web servers, the
"redirect" enhancement). The changes here would probably be either a new
"ciphersuite" enhancement in each plugin that provides an installer,
or a family of enhancements, one per selectable ciphersuite configuration.
