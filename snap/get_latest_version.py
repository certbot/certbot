#!/usr/bin/env python3
import sys

import requests
from packaging import version


def main():
    result = requests.get('https://api.github.com/repos/certbot/certbot/tags')
    result.raise_for_status()

    tags = [version.parse(entry['name'].replace('v', '')) for entry in result.json()]
    tags.sort()

    latest_tag = 'v{0}'.format(tags[-1])

    sys.stdout.write(latest_tag)


if __name__ == '__main__':
    main()
