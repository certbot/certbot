from setuptools import find_packages
from setuptools import setup

version = '1.0'

setup(
    name='windows-installer',
    version=version,
    description='Environment to build the Certbot Windows installer',
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Software Development :: Build Tools',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        # pynsist is pinned to an exact version so we can update
        # assets/template.nsi as needed. The file is based on the default
        # pynsist NSIS template and pynsist's documentation warns that custom
        # templates may need to be updated for them to work with new versions
        # of pynsist. See
        # https://pynsist.readthedocs.io/en/latest/cfgfile.html#build-section.
        'pynsist==2.7'
    ],
    entry_points={
        'console_scripts': [
            'construct-windows-installer = windows_installer.construct:main',
        ],
    },
)
