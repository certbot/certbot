#!/usr/bin/env python
"""Uses pip to upgrade Python packaging tools to pinned versions."""
import pip_install


def main():
    pip_install.pipstrap()


if __name__ == '__main__':
    main()
