set -euxo pipefail
while true; do
    remove_untagged_docker.sh || ./build.sh v2.3.1 all && ./test.sh v2.3.1 all
done
