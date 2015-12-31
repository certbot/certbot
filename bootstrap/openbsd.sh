#!/bin/sh -e

pkg_add -aI \
  py-pip \
  augeas \
  libffi \

if [ ! -e /usr/local/bin/pip ] &&
[ ! -e /usr/local/bin/python ] &&
[ ! -e /usr/local/bin/2to3 ] &&
[ ! -e /usr/local/bin/python-config ] &&
[ ! -e /usr/local/bin/pydoc ]; then
	echo 'No system default Python and pip found; setting the default to Python 2.7'
	ln -s /usr/local/bin/pip2.7 /usr/local/bin/pip
	ln -s /usr/local/bin/python2.7 /usr/local/bin/python
	ln -s /usr/local/bin/python2.7-2to3 /usr/local/bin/2to3
	ln -s /usr/local/bin/python2.7-config /usr/local/bin/python-config
	ln -s /usr/local/bin/pydoc2.7  /usr/local/bin/pydoc
else
	if python -V 2>&1 | fgrep -q 'Python 2.7.' &&
	   pip -V | fgrep -q '(python 2.7)'; then
		pip install virtualenv
	else
		echo 'Defaults for Python and pip were found, but they were not set to Python 2.7.'
		echo 'Please make sure that the system default Python and pip are for Python 2.7 by'
		echo 'creating symbolic links as root like so (overwriting any previous default):'
		echo
		echo '    ln -sf /usr/local/bin/python2.7 /usr/local/bin/python'
		echo '    ln -sf /usr/local/bin/python2.7-2to3 /usr/local/bin/2to3'
		echo '    ln -sf /usr/local/bin/python2.7-config /usr/local/bin/python-config'
		echo '    ln -sf /usr/local/bin/pydoc2.7  /usr/local/bin/pydoc'
		echo '    ln -sf /usr/local/bin/pip2.7 /usr/local/bin/pip'
		exit 1
	fi
fi
