#!/bin/bash
python multitester.py targets.yaml travis-test-farm.pem SET_BY_ENV scripts/test_leauto_upgrades.sh --repo "$TRAVIS_BUILD_DIR" --branch "$TRAVIS_BRANCH" --fast
cat letest-*/*.log
