#!/bin/sh

# Tested on mageia 5 x86_64
if ! urpmi --force  \
       python \
       libpython-devel \
       python-virtualenv
then
  echo "Could not install Python dependencies. Aborting bootstrap!"
  exit 1
fi

if ! urpmi --force \
       git \
       gcc \
       cdialog \
       python-augeas \
       libopenssl-devel \
       libffi-devel \
       rootcerts
then
    echo "Could not install additional dependencies. Aborting bootstrap!"
    exit 1
fi
