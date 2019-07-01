"""Certbot client."""
import distutils
import imp
import importlib
importlib.reload(imp)


# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '0.36.0.dev0'

for mod in (distutils, imp,):
    print(mod.__file__)
    with open(mod.__file__) as f:
        print(f.read())
