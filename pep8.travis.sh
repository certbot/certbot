#!/bin/sh

set -e  # Fail fast

pep8 --config=acme/.pep8 acme
