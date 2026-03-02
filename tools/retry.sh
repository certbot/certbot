#!/bin/bash
# Retries a command if it fails.
#
# This is based on travis_retry.bash
# https://github.com/travis-ci/travis-build/blob/master/lib/travis/build/bash/travis_retry.bash.
set -e
result=0
count=1
while [[ "${count}" -le 3 ]]; do
  result=0
  "${@}" || result="${?}"
  if [[ $result -eq 0 ]]; then break; fi
  count="$((count + 1))"
  sleep 1
done

exit "${result}"
