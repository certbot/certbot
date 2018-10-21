#!/usr/bin/env python
import argparse
import subprocess
import os

DEFAULT_PACKAGES = [
    'certbot','acme','certbot_apache','certbot_dns_cloudflare','certbot_dns_cloudxns',
    'certbot_dns_digitalocean','certbot_dns_dnsimple','certbot_dns_dnsmadeeasy',
    'certbot_dns_gehirn','certbot_dns_google','certbot_dns_linode','certbot_dns_luadns',
    'certbot_dns_nsone','certbot_dns_ovh','certbot_dns_rfc2136','certbot_dns_route53',
    'certbot_dns_sakuracloud','certbot_nginx','certbot_postfix','letshelp_certbot']

COVER_THRESHOLDS = {
    'certbot': 98,
    'acme': 100,
    'certbot_apache': 100,
    'certbot_dns_cloudflare': 98,
    'certbot_dns_cloudxns': 99,
    'certbot_dns_digitalocean': 98,
    'certbot_dns_dnsimple': 98,
    'certbot_dns_dnsmadeeasy': 99,
    'certbot_dns_gehirn': 97,
    'certbot_dns_google': 99,
    'certbot_dns_linode': 98,
    'certbot_dns_luadns': 98,
    'certbot_dns_nsone': 99,
    'certbot_dns_ovh': 97,
    'certbot_dns_rfc2136': 99,
    'certbot_dns_route53': 92,
    'certbot_dns_sakuracloud': 97,
    'certbot_nginx': 97,
    'certbot_postfix': 100,
    'letshelp_certbot': 100
}

def cover(package):
    threshold = COVER_THRESHOLDS[package]

    if not threshold:
        raise ValueError('Unrecognized package: {0}'.format(package))

    pkg_dir = package.replace('_', '-')
    subprocess.call([
        sys.executable, '-m', 'pytest' , '--cov', pkg_dir, '--cov-append', '--cov-report=',
        '--numprocesses', 'auto', '--pyargs', package])
    subprocess.call([
        sys.executable, '-m', 'coverage', 'report', '--fail-under', str(threshold), '--include',
        '{0}/*'.format(pkg_dir), '--show-missing'])

def main():
    description="""
This script is used by tox.ini (and thus by Travis CI and AppVeyor) in order
to generate separate stats for each package. It should be removed once those
packages are moved to a separate repo.

Option -e makes sure we fail fast and don't submit to codecov."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--packages', nargs='+')

    args = parser.parse_args()

    packages = args.packages or DEFAULT_PACKAGES

    # --cov-append is on, make sure stats are correct
    try:
        os.remove('.coverage')
    except OSError:
        pass

    for package in packages:
        cover(package)

if __name__ == '__main__':
    main()
