#!/usr/bin/env python

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools import Command
from distutils.errors import DistutilsPlatformError
import os
import subprocess
from distutils.spawn import find_executable

proto = [ 'trustify/protocol/chocolate.proto' ]

class build_py_with_protobuf(build_py):
    protoc = find_executable("protoc")

    def run_protoc(self, proto):
        try:
            proc = subprocess.Popen(
                [self.protoc, '--python_out', '.', proto],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError, ex:
            if ex.errno == errno.ENOENT:
                print ("Could not find protoc command. Make sure protobuf is "
                    "installed and your PATH environment is set.")
                raise DistutilsPlatformError("Failed to generate protbuf "
                    "files with protoc.")
            else:
                raise
        out = proc.communicate()[0]
        result = proc.wait()
        if result != 0:
            print "Error during protobuf files generation with protoc:"
            print out
            raise DistutilsPlatformError("Failed to generate protobuf "
                "files with protoc.")

    def run(self):
        for p in proto:
            self.run_protoc(p)

        build_py.run(self)

class clean_with_protobuf(Command):
    user_options = [("all", "a", "")]

    def initialize_options(self):
        self.all = True
        pass

    def finalize_options(self):
        pass

    def run(self):
        for p in proto:
            pb2 = p.replace(".proto", "_pb2.py")
            if not os.path.exists(pb2):
                continue
            os.unlink(pb2)

setup(
    name="trustify",
    version="0.1",
    description="Trustify",
    author="Trustify project",
    license="",
    url="https://trustify.net/",
    packages=[
        'trustify',
        'trustify.protocol',
        'trustify.client',
    ],
    install_requires=[
        #'dialog',
        'requests>=2.4.3',
        'protobuf',
        'python-augeas',
        'pycrypto',
        'M2Crypto',
    ],
    entry_points={
        'console_scripts': [
            'trustify = trustify.client.client:authenticate'
        ]
    },
    cmdclass={
        'build_py': build_py_with_protobuf,
        'clean': clean_with_protobuf,
    },
)
