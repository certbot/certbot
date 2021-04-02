from setuptools import find_packages
from setuptools import setup

version = '1.0'

setup(
    name='windows-installer',
    version=version,
    description='Environment to build the Certbot Windows installer',
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Software Development :: Build Tools',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'pynsist==2.7'
    ],
    entry_points={
        'console_scripts': [
            'construct-windows-installer = windows_installer.construct:main',
        ],
    },
)
