#!/usr/bin/env python
"""Uses pip to upgrade Python packaging tools to pinned versions."""
import pip_install


def main():
    pip_install.main('pip setuptools wheel'.split())


if __name__ == '__main__':
    main()
