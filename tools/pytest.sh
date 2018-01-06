#!/bin/bash
# Runs pytest with the provided arguments, adding --numprocesses to the command
# line. This argument is set to "auto" if the environmnent variable TRAVIS is
# not set, otherwise, it is set to 2. This works around
# https://github.com/pytest-dev/pytest-xdist/issues/9. Currently every Travis
# environnment provides two cores. See
# https://docs.travis-ci.com/user/reference/overview/#Virtualization-environments.

pytest --numprocesses auto --max-slave-restart 0 -vvvv "$@"
