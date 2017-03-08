from setuptools import setup


setup(
    name='certbot-example-plugins',
    package='certbot_example_plugins.py',
    install_requires=[
        'certbot',
        'zope.interface',
    ],
    entry_points={
        'certbot.plugins': [
            'example_authenticator = certbot_example_plugins:Authenticator',
            'example_installer = certbot_example_plugins:Installer',
        ],
    },
)
