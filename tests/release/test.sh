#!/bin/sh -e
release_test_dir=$(realpath $(dirname $0))
release_openssl_privkey="$release_test_dir/fake.pem"
export RELEASE_OPENSSL_PUBKEY="$release_test_dir/fake.pub"

export GNUPGHOME=$(mktemp -d)
gpg --import "$release_test_dir/fake.asc"
export RELEASE_GPG_KEY=$(gpg --fingerprint | sed -n 's/ //g; s/.*fingerprint=\(\)/\1/p')

cd $(mktemp -d)
git clone --single-branch "$release_test_dir/../.." .
release_num="0.99.0"
git checkout -b "candidate-$release_num"

need_sig=true
yes | tools/release.sh --production $release_num 0.999.0 |
while read line; do
    if $need_sig && [ "$line" = "Verification Failure" ]; then
        openssl dgst -sha256 -sign $release_openssl_privkey -out \
            releases/le*/letsencrypt-auto-source/letsencrypt-auto.sig \
            releases/le*/letsencrypt-auto-source/letsencrypt-auto
        need_sig=false
    fi
done
