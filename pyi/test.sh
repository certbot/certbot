#!/bin/sh -xe

tmp=$(mktemp -d)
for bin in ./dist/letsencrypt ./dist/folder/letsencrypt-bin
do
    $bin \
        --config-dir $tmp/config \
        --work-dir $tmp/work \
        --logs-dir $tmp/logs \
        "$@"
done
