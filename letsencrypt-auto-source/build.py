#!/usr/bin/env python
"""Stitch together the letsencrypt-auto script.

Implement a simple templating language in which {{ some/file }} turns into the
contents of the file at ./pieces/some/file except for certain tokens which have
other, special definitions.

"""
from os.path import abspath, dirname, join
import re

from version import certbot_version, file_contents


DIR = dirname(abspath(__file__))


def build(version=None, requirements=None):
    """Return the built contents of the letsencrypt-auto script.

    :arg version: The version to attach to the script. Default: the version of
        the certbot package
    :arg requirements: The contents of the requirements file to embed. Default:
        contents of dependency-requirements.txt, letsencrypt-requirements.txt,
        and certbot-requirements.txt

    """
    special_replacements = {
        'LE_AUTO_VERSION': version or certbot_version(DIR)
    }
    if requirements:
        special_replacements['dependency-requirements.txt'] = ''
        special_replacements['letsencrypt-requirements.txt'] = ''
        special_replacements['certbot-requirements.txt'] = requirements

    def replacer(match):
        token = match.group(1)
        if token in special_replacements:
            return special_replacements[token]
        else:
            return file_contents(join(DIR, 'pieces', token))

    return re.sub(r'{{\s*([A-Za-z0-9_./-]+)\s*}}',
                  replacer,
                  file_contents(join(DIR, 'letsencrypt-auto.template')))


def main():
    with open(join(DIR, 'letsencrypt-auto'), 'w') as out:
        out.write(build())


if __name__ == '__main__':
    main()
