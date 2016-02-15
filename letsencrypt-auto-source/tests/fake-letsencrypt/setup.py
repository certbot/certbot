from setuptools import setup


setup(
    name='letsencrypt',
    version='99.9.9',
    description='A mock version of letsencrypt that just prints its version',
    py_modules=['letsencrypt'],
    entry_points={
        'console_scripts': ['letsencrypt = letsencrypt:main']
    }
)
