#!/bin/sh
uri_path=".well-known/acme-challenge/$CERTBOT_TOKEN"

# This script should be run from the top level. e.g. ./tests/manual-http-auth.sh
source_dir="$(pwd)"
cd $(mktemp -d)
mkdir -p $(dirname $uri_path)
echo $CERTBOT_VALIDATION > $uri_path
python "$source_dir/tests/run_http_server.py" $http_01_port >/dev/null 2>&1 &
server_pid=$!
while ! curl "http://localhost:$http_01_port/$uri_path" >/dev/null 2>&1; do
    sleep 1s
done
echo $server_pid
