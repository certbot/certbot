#!/bin/bash
set -e

uname_output=$(/bin/uname_orig "$@")

if [ "$UNAME_FAKE_32BITS" = true ]; then
    uname_output="${uname_output//x86_64/i686}"
fi

echo "$uname_output"
