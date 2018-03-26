
## Automated testing for STARTTLS Everywhere + Postfix plugin

Unfortunately, Postfix isn't extra-ordinarily "dockerizable" -- it's already architected as a set of microservices running as individual processes, which each report logs to rsyslog. But, containerizing Postfix still comes with benefits (ease of testing, ease of use, etc) so we'll do it anyways.

Spin up two Postfix containers, a sender and a receiver-- we'll use Docker's embedded DNS for the sender to discover the receiver. The sender must run tests against itself depending on which receiver it's talking to.

The receiver should have three separate certs for testing:
 1. example.com, with a valid root in trust chain.
 2. example.com, but self-signed (no valid root in trust chain)
 3. evil.com, with a valid root in trust chain.

The certs with "valid trust chains" can bootstrap this trust by copying themselves into /etc/ssl/certs for testing.

So we can test the following failure cases:
 1. The receiver doesn't support TLS.
 2. The receiver's certificate is self-signed, and not pinned.
 3. Policy says cert should be valid for example.com, but cert is instead valid for evil.com.

And the following success case:
 1. Receiver supports TLS, and their cert CN is valid according to policy.
    - Could mean that 1) their cert is pinned, or 2) their cert has a root in the trust chain. Or both.



