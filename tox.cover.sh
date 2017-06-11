#!/bin/sh -xe

# USAGE: ./tox.cover.sh [package]
#
# This script is used by tox.ini (and thus Travis CI) in order to
# generate separate stats for each package. It should be removed once
# those packages are moved to separate repo.
#
# -e makes sure we fail fast and don't submit coveralls submit

if [ "xxx$1" = "xxx" ]; then
  pkgs="certbot acme certbot_apache certbot_dns_cloudflare certbot_dns_cloudxns certbot_dns_digitalocean certbot_dns_dnsimple certbot_dns_google certbot_dns_nsone certbot_dns_route53 certbot_nginx letshelp_certbot"
else
  pkgs="$@"
fi

cover () {
  if [ "$1" = "certbot" ]; then
    min=98
  elif [ "$1" = "acme" ]; then
    min=100
  elif [ "$1" = "certbot_apache" ]; then
    min=100
  elif [ "$1" = "certbot_dns_cloudflare" ]; then
    min=98
  elif [ "$1" = "certbot_dns_cloudxns" ]; then
    min=99
  elif [ "$1" = "certbot_dns_digitalocean" ]; then
    min=98
  elif [ "$1" = "certbot_dns_dnsimple" ]; then
    min=98
  elif [ "$1" = "certbot_dns_google" ]; then
    min=99
  elif [ "$1" = "certbot_dns_nsone" ]; then
    min=99
  elif [ "$1" = "certbot_dns_route53" ]; then
    min=99
  elif [ "$1" = "certbot_nginx" ]; then
    min=97
  elif [ "$1" = "letshelp_certbot" ]; then
    min=100
  else
    echo "Unrecognized package: $1"
    exit 1
  fi

  # "-c /dev/null" makes sure setup.cfg is not loaded (multiple
  # --with-cover add up, --cover-erase must not be set for coveralls
  # to get all the data); --with-cover scopes coverage to only
  # specific package, positional argument scopes tests only to
  # specific package directory; --cover-tests makes sure every tests
  # is run (c.f. #403)
  nosetests -c /dev/null --with-cover --cover-tests --cover-package  \
            "$1" --cover-min-percentage="$min" "$1"
}

rm -f .coverage  # --cover-erase is off, make sure stats are correct
for pkg in $pkgs
do
  cover $pkg
done
