#!/bin/bash -eux
#
# Runs test farm tests in Travis.
cd $(dirname "$0")

openssl aes-256-cbc -K $encrypted_9a387195a62e_key -iv $encrypted_9a387195a62e_iv -in travis-test-farm.pem.enc -out travis-test-farm.pem -d

python multitester.py apache2_targets.yaml ./travis-test-farm.pem none scripts/test_apache2.sh
for script in test_leauto_upgrades.sh test_letsencrypt_auto_certonly_standalone.sh test_sdists.sh; do
    # Sleep after each test to give AWS time to terminate instances.
    sleep 30s
    python multitester.py targets.yaml ./travis-test-farm.pem none "scripts/$script"
done
