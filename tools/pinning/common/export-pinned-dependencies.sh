#!/bin/bash
# This script accepts a directory containing a pyproject.toml file configured
# for use with poetry and generates and prints the pinned dependencies of that
# file. Any dependencies on acme or those referencing certbot will be removed
# from the output. The exported requirements are printed to stdout.
#
# For example, if a directory containing a pyproject.toml file for poetry is at
# ../current, you could activate Certbot's developer environment and then run a
# command like the following to generate requirements.txt for that environment:
#   ./export-pinned-dependencies.sh ../current > requirements.txt
set -euo pipefail

# If this script wasn't given a command line argument, print usage and exit.
if [ -z ${1+x} ]; then
    echo "Usage:" >&2
    echo "$0 PYPROJECT_TOML_DIRECTORY [POETRY_ARGS]" >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORK_DIR="$1"

if ! command -v poetry >/dev/null || [ $(poetry --version | grep -oE '[0-9]+\.[0-9]+' | sed 's/\.//') -lt 12 ]; then
    echo "Please install poetry 1.2+." >&2
    echo "You may need to recreate Certbot's virtual environment and activate it." >&2
    exit 1
fi

# Old eggs can cause outdated dependency information to be used by poetry so we
# delete them before generating the lock file. See
# https://github.com/python-poetry/poetry/issues/4103 for more info.
rm -rf ${REPO_ROOT}/*/*.egg-info
rm -rf ${REPO_ROOT}/*/src/*.egg-info

cd "${WORK_DIR}"

if [ -f poetry.lock ]; then
    rm poetry.lock
fi

echo "If this takes more than a few minutes, you may want to try clearing poetry's" >&2
echo "caches with a command like the following and running this script again:" >&2
echo >&2
echo "    poetry cache list | xargs -L1 poetry cache clear --all" >&2
echo >&2
echo "If that doesn't help, you can also try running this script with extra arguments" >&2
echo 'for "poetry lock" on the command line such as -vvv to help see where poetry is' >&2
echo "getting stuck." >&2
extra_args="${*:2}"
poetry lock ${extra_args:+"$extra_args"} >&2
trap 'rm poetry.lock' EXIT

# POETRY_WARNINGS_EXPORT is set to remove warning output about
# poetry-plugin-export no longer being installed with poetry by default in the
# future which we can ignore because we explicitly depend on the plugin
# package.
#
# sed is then used to remove local packages from the output.
POETRY_WARNINGS_EXPORT=false poetry export --format constraints.txt --without-hashes | sed '/^acme @/d; /certbot/d;'
