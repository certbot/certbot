#!/usr/bin/env python
"""Ensures there have been no changes to important certbot-auto files."""

import hashlib
import os

# Relative to the root of the Certbot repo, these files are expected to exist
# and have the SHA-256 hashes contained in this dictionary. These hashes were
# taken from our v1.14.0 tag which was the last release we intended to make
# changes to certbot-auto.
#
# We can delete this script and the files under letsencrypt-auto-source when
# we're comfortable breaking any old certbot-auto scripts that haven't updated
# to the last version of the script yet.  See
# https://opensource.eff.org/eff-open-source/pl/65geri7c4tr6iqunc1rpb3mpna and
# letsencrypt-auto-source/README.md for more info.
EXPECTED_FILES = {
    os.path.join('letsencrypt-auto-source', 'letsencrypt-auto'):
        'b997e3608526650a08e36e682fc3bf0c29903c06fa5ba4cc49308c43832450c2',
    os.path.join('letsencrypt-auto-source', 'letsencrypt-auto.sig'):
        '61c036aabf75da350b0633da1b2bef0260303921ecda993455ea5e6d3af3b2fe',
}


def find_repo_root():
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def sha256_hash(filename):
    hash_object = hashlib.sha256()
    with open(filename, 'rb') as f:
        hash_object.update(f.read())
    return hash_object.hexdigest()


def main():
    repo_root = find_repo_root()
    for filename, expected_hash in EXPECTED_FILES.items():
        filepath = os.path.join(repo_root, filename)
        assert sha256_hash(filepath) == expected_hash, f'unexpected changes to {filepath}'
    print('All certbot-auto files have correct hashes.')


if __name__ == '__main__':
    main()
