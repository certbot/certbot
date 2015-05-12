#!/bin/sh

# This script is used by tox.ini (and thus Travis CI) in order to
# generate separate stats for each package. It should be removed once
# those packages are moved to separate repo.

cover () {
  # "-c /dev/null" makes sure setup.cfg is not loaded (multiple
  # --with-cover add up, --cover-erase must not be set for coveralls
  # to get all the data); --with-cover scopes coverage to only
  # specific package, positional argument scopes tests only to
  # specific package directory; --cover-tests makes sure every tests
  # is run (c.f. #403)
  nosetests -c /dev/null --with-cover --cover-tests --cover-package  \
            "$1" --cover-min-percentage="$2" "$1"
}

# don't use sequential composition (;), if letsencrypt_nginx returns
# 0, coveralls submit will be triggered (c.f. .travis.yml,
# after_success)
cover letsencrypt 94 && cover acme 100 && \
    cover letsencrypt_apache 78 && cover letsencrypt_nginx 96
