from setuptools import find_packages
from setuptools import setup

version = '0.32.0.dev0'

install_requires = [
    'coverage',
    'cryptography',
    'pyopenssl',
    'pytest',
    'pytest-cov',
    # This version is needed for "worker" attributes we currently use like
    # "workerinput".  See https://github.com/pytest-dev/pytest-xdist/pull/268.
    'pytest-xdist>=1.22.1',
    'python-dateutil',
    # This dependency needs to be added using environment markers to avoid its
    # installation on Linux.
    'pywin32>=300 ; sys_platform == "win32"',
    'pyyaml',
    'pytz>=2019.3',
    # requests unvendored its dependencies in version 2.16.0 and this code relies on that for
    # calling `urllib3.disable_warnings`.
    'requests>=2.16.0',
    'types-python-dateutil',
]

setup(
    name='certbot-ci',
    version=version,
    description="Certbot continuous integration framework",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.9',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,

    entry_points={
        'console_scripts': [
            'certbot_test=certbot_integration_tests.utils.certbot_call:main',
            'run_acme_server=certbot_integration_tests.utils.acme_server:main',
        ],
    }
)
