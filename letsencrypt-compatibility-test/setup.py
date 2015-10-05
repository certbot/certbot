from setuptools import setup
from setuptools import find_packages


version = '0.1.0.dev0'

install_requires = [
    'letsencrypt=={0}'.format(version),
    'letsencrypt-apache=={0}'.format(version),
    'letsencrypt-nginx=={0}'.format(version),
    'docker-py',
    'mock<1.1.0',  # py26
    'zope.interface',
]

setup(
    name='letsencrypt-compatibility-test',
    version=version,
    description="Compatibility tests for Let's Encrypt client",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'letsencrypt-compatibility-test = letsencrypt_compatibility_test.test_driver:main',
        ],
    },
)
