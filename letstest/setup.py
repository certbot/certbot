from setuptools import find_packages
from setuptools import setup

setup(
    name='letstest',
    version='1.0',
    description='Test Certbot on different AWS images',
    url='https://github.com/certbot/certbot',
    author='Certbot Project',
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        # awscli isn't required by the tests themselves, but it is a useful
        # tool to have when using these tests to generate keys and control
        # running instances so the dependency is declared here for convenience.
        'awscli',
        'boto3',
        'botocore',
        # The API from Fabric 2.0+ is used instead of the 1.0 API.
        'fabric>=2',
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'letstest=letstest.multitester:main',
        ],
    }
)
