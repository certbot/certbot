#!/bin/sh
# This is a simple script that can be sourced to set Python environment
# variables for use in Certbot's letstest test farm tests.

# Some distros like Fedora may only have an executable named python3 installed.
if command -v python; then
    PYTHON_NAME="python"
    VENV_SCRIPT="tools/venv.py"
    VENV_PATH="venv"
else
    # We could check for "python2" here, however, the addition of "python3"
    # only systems is what necessitated this change so checking for "python2"
    # isn't necessary.
    PYTHON_NAME="python3"
    VENV_PATH="venv3"
    VENV_SCRIPT="tools/venv3.py"
fi
