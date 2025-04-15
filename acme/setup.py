from setuptools import find_packages
from setuptools import setup

version = '4.1.0.dev0'

install_requires = [
    'cryptography>=43.0.0',
    'josepy>=2.0.0',
    # PyOpenSSL>=25.0.0 is just needed to satisfy mypy right now so this dependency can probably be
    # relaxed to >=24.0.0 if needed.
    'PyOpenSSL>=25.0.0',
    'pyrfc3339',
    'pytz>=2019.3',
    'requests>=2.20.0',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

test_extras = [
    'pytest',
    'pytest-xdist',
    'typing-extensions',
]

setup(
    name='acme',
    version=version,
    description='ACME protocol implementation in Python',
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.9',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
        'test': test_extras,
    },
)
