from setuptools import setup


setup(
    name='letsencrypt-example-plugins',
    package='letsencrypt_example_plugins.py',
    install_requires=[
        'letsencrypt',
        'zope.interface',
    ],
    entry_points={
        'letsencrypt.plugins': [
            'example_authenticator = letsencrypt_example_plugins:Authenticator',
            'example_installer = letsencrypt_example_plugins:Installer',
        ],
    },
)
