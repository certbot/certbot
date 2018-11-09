"""
Compatibility layer to run certbot both on Linux and Windows.

The approach used here is similar to Modernizr for Web browsers.
We do not check the platform type to determine if a particular logic is supported.
Instead, we apply a logic, and then fallback to another logic if first logic
is not supported at runtime.

Then logic chains are abstracted into single functions to be exposed to certbot.
"""
