from setuptools import setup
from setuptools import find_packages


install_requires = ["mock<1.1.0",]

setup(
    name="letshelp-letsencrypt",
    packages=find_packages(),
    install_requires=install_requires,
)
