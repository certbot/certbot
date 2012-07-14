#!/usr/bin/env python2.3
"""Implement Hashcash version 1 protocol in Python
+-------------------------------------------------------+
| Written by David Mertz; released to the Public Domain |
+-------------------------------------------------------+

Double spend database not implemented in this module, but stub
for callbacks is provided in the 'check()' function

The function 'check()' will validate hashcash v1 and v0 tokens, as well as
'generalized hashcash' tokens generically.  Future protocol version are
treated as generalized tokens (should a future version be published w/o
this module being correspondingly updated).

A 'generalized hashcash' is implemented in the '_mint()' function, with the
public function 'mint()' providing a wrapper for actual hashcash protocol.
The generalized form simply finds a suffix that creates zero bits in the
hash of the string concatenating 'challenge' and 'suffix' without specifying
any particular fields or delimiters in 'challenge'.  E.g., you might get:

    >>> from hashcash import mint, _mint
    >>> mint('foo', bits=16)
    '1:16:040922:foo::+ArSrtKd:164b3'
    >>> _mint('foo', bits=16)
    '9591'
    >>> from sha import sha
    >>> sha('foo9591').hexdigest()
    '0000de4c9b27cec9b20e2094785c1c58eaf23948'
    >>> sha('1:16:040922:foo::+ArSrtKd:164b3').hexdigest()
    '0000a9fe0c6db2efcbcab15157735e77c0877f34'

Notice that '_mint()' behaves deterministically, finding the same suffix
every time it is passed the same arguments.  'mint()' incorporates a random
salt in stamps (as per the hashcash v.1 protocol).
"""
import sys
from string import ascii_letters
from math import ceil, floor
from sha import sha
from random import choice
from time import strftime, localtime, time

ERR = sys.stderr            # Destination for error messages
DAYS = 60 * 60 * 24         # Seconds in a day
tries = [0]                 # Count hashes performed for benchmark

def mint(resource, bits=20, now=None, ext='', saltchars=8, stamp_seconds=False):
    """Mint a new hashcash stamp for 'resource' with 'bits' of collision

    20 bits of collision is the default.

    'ext' lets you add your own extensions to a minted stamp.  Specify an
    extension as a string of form 'name1=2,3;name2;name3=var1=2,2,val'
    FWIW, urllib.urlencode(dct).replace('&',';') comes close to the
    hashcash extension format.

    'saltchars' specifies the length of the salt used; this version defaults
    8 chars, rather than the C version's 16 chars.  This still provides about
    17 million salts per resource, per timestamp, before birthday paradox
    collisions occur.  Really paranoid users can use a larger salt though.

    'stamp_seconds' lets you add the option time elements to the datestamp.
    If you want more than just day, you get all the way down to seconds,
    even though the spec also allows hours/minutes without seconds.
    """
    ver = "1"
    now = now or time()
    if stamp_seconds: ts = strftime("%y%m%d%H%M%S", localtime(now))
    else:             ts = strftime("%y%m%d", localtime(now))
    challenge = "%s:"*6 % (ver, bits, ts, resource, ext, _salt(saltchars))
    return challenge + _mint(challenge, bits)

def _salt(l):
    "Return a random string of length 'l'"
    alphabet = ascii_letters + "+/="
    return ''.join([choice(alphabet) for _ in [None]*l])

def _mint(challenge, bits):
    """Answer a 'generalized hashcash' challenge'

    Hashcash requires stamps of form 'ver:bits:date:res:ext:rand:counter'
    This internal function accepts a generalized prefix 'challenge',
    and returns only a suffix that produces the requested SHA leading zeros.

    NOTE: Number of requested bits is rounded up to the nearest multiple of 4
    """
    counter = 0
    hex_digits = int(ceil(bits/4.))
    zeros = '0'*hex_digits
    while 1:
        digest = sha(challenge+hex(counter)[2:]).hexdigest()
        if digest[:hex_digits] == zeros:
            tries[0] = counter
            return hex(counter)[2:]
        counter += 1

def check(stamp, resource=None, bits=None,
                 check_expiration=None, ds_callback=None):
    """Check whether a stamp is valid

    Optionally, the stamp may be checked for a specific resource, and/or
    it may require a minimum bit value, and/or it may be checked for
    expiration, and/or it may be checked for double spending.

    If 'check_expiration' is specified, it should contain the number of
    seconds old a date field may be.  Indicating days might be easier in
    many cases, e.g.

      >>> from hashcash import DAYS
      >>> check(stamp, check_expiration=28*DAYS)

    NOTE: Every valid (version 1) stamp must meet its claimed bit value
    NOTE: Check floor of 4-bit multiples (overly permissive in acceptance)
    """
    if stamp.startswith('0:'):          # Version 0
        try:
            date, res, suffix = stamp[2:].split(':')
        except ValueError:
            ERR.write("Malformed version 0 hashcash stamp!\n")
            return False
        if resource is not None and resource != res:
            return False
        elif check_expiration is not None:
            good_until = strftime("%y%m%d%H%M%S", localtime(time()-check_expiration))
            if date < good_until:
                return False
        elif callable(ds_callback) and ds_callback(stamp):
            return False
        elif type(bits) is not int:
            return True
        else:
            hex_digits = int(floor(bits/4))
            return sha(stamp).hexdigest().startswith('0'*hex_digits)
    elif stamp.startswith('1:'):        # Version 1
        try:
            claim, date, res, ext, rand, counter = stamp[2:].split(':')
        except ValueError:
            ERR.write("Malformed version 1 hashcash stamp!\n")
            return False
        if resource is not None and resource != res:
            return False
        elif type(bits) is int and bits > int(claim):
            return False
        elif check_expiration is not None:
            good_until = strftime("%y%m%d%H%M%S", localtime(time()-check_expiration))
            if date < good_until:
                return False
        elif callable(ds_callback) and ds_callback(stamp):
            return False
        else:
            hex_digits = int(floor(int(claim)/4))
            return sha(stamp).hexdigest().startswith('0'*hex_digits)
    else:                               # Unknown ver or generalized hashcash
        ERR.write("Unknown hashcash version: Minimal authentication!\n")
        if type(bits) is not int:
            return True
        elif resource is not None and stamp.find(resource) < 0:
            return False
        else:
            hex_digits = int(floor(bits/4))
            return sha(stamp).hexdigest().startswith('0'*hex_digits)

def is_doublespent(stamp):
    """Placeholder for double spending callback function

    The check() function may accept a 'ds_callback' argument, e.g.
      check(stamp, "mertz@gnosis.cx", bits=20, ds_callback=is_doublespent)

    This placeholder simply reports stamps as not being double spent.
    """
    return False

if __name__=='__main__':
    # Import Psyco if available
    try:
        import psyco
        psyco.bind(_mint)
    except ImportError:
        pass
    import optparse
    out, err = sys.stdout.write, sys.stderr.write
    parser = optparse.OptionParser(version="%prog 0.1",
                      usage="%prog -c|-m [-b bits] [string|STDIN]")
    parser.add_option('-b', '--bits', type='int', dest='bits', default=20,
                      help="Specify required collision bits" )
    parser.add_option('-m', '--mint', help="Mint a new stamp",
                      action='store_true', dest='mint')
    parser.add_option('-c', '--check', help="Check a stamp for validity",
                      action='store_true', dest='check')
    parser.add_option('-s', '--timer', help="Time the operation performed",
                      action='store_true', dest='timer')
    parser.add_option('-n', '--raw', help="Suppress trailing newline",
                      action='store_true', dest='raw')
    (options, args) = parser.parse_args()
    start = time()
    if options.mint:    action = mint
    elif options.check: action = check
    else:
        out("Try: %s --help\n" % sys.argv[0])
        sys.exit()
    if args: out(str(action(args[0], bits=options.bits)))
    else:    out(str(action(sys.stdin.read(), bits=options.bits)))
    if not options.raw: sys.stdout.write('\n')
    if options.timer:
        timer = time()-start
        err("Completed in %0.4f seconds (%d hashes per second)\n" %
            (timer, tries[0]/timer))

