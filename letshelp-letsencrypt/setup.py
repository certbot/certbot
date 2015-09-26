import sys

from setuptools import setup
from setuptools import find_packages


version = "0.1.0.dev0"

install_requires = [
    "setuptools",  # pkg_resources
]
if sys.version_info < (2, 7):
    install_requires.append("mock<1.1.0")
else:
    install_requires.append("mock")

setup(
    name="letshelp-letsencrypt",
    version=version,
    description="Let's help Let's Encrypt client",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
    author_email='client-dev@letsencrypt.org',
    license="Apache License 2.0",

    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "letshelp-letsencrypt-apache = letshelp_letsencrypt.apache:main",
        ],
    },
    include_package_data=True,
)
