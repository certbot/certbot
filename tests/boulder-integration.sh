#!/bin/bash
# Simple integration test. Make sure to activate virtualenv beforehand
# (source venv/bin/activate) and that you are running Boulder test
# instance (see ./boulder-fetch.sh).
#
# Environment variables:
#   SERVER: Passed as "certbot --server" argument.
#
# Note: this script is called by Boulder integration test suite!

set -eux

. ./tests/integration/_common.sh
export PATH="$PATH:/usr/sbin"  # /usr/sbin/nginx

cleanup_and_exit() {
    EXIT_STATUS=$?
    if SERVER_STILL_RUNNING=`ps -p $python_server_pid -o pid=`
    then
        echo Kill server subprocess, left running by abnormal exit
        kill $SERVER_STILL_RUNNING
    fi
    if [ -f "$HOOK_DIRS_TEST" ]; then
        rm -f "$HOOK_DIRS_TEST"
    fi
    exit $EXIT_STATUS
}

trap cleanup_and_exit EXIT

export HOOK_DIRS_TEST="$(mktemp)"
renewal_hooks_root="$config_dir/renewal-hooks"
renewal_hooks_dirs=$(echo "$renewal_hooks_root/"{pre,deploy,post})
renewal_dir_pre_hook="$(echo $renewal_hooks_dirs | cut -f 1 -d " ")/hook.sh"
renewal_dir_deploy_hook="$(echo $renewal_hooks_dirs | cut -f 2 -d " ")/hook.sh"
renewal_dir_post_hook="$(echo $renewal_hooks_dirs | cut -f 3 -d " ")/hook.sh"

# Creates hooks in Certbot's renewal hook directory that write to a file
CreateDirHooks() {
    for hook_dir in $renewal_hooks_dirs; do
        mkdir -p $hook_dir
        hook_path="$hook_dir/hook.sh"
        cat << EOF > "$hook_path"
#!/bin/bash -xe
if [ "\$0" = "$renewal_dir_deploy_hook" ]; then
    if [ -z "\$RENEWED_DOMAINS" -o -z "\$RENEWED_LINEAGE" ]; then
        echo "Environment variables not properly set!" >&2
        exit 1
    fi
fi
echo \$(basename \$(dirname "\$0")) >> "\$HOOK_DIRS_TEST"
EOF
        chmod +x "$hook_path"
    done
}

# Asserts that the hooks created by CreateDirHooks have been run once and
# resets the file.
#
# Arguments:
#     The number of times the deploy hook should have been run. (It should run
#     once for each certificate that was issued in that run of Certbot.)
CheckDirHooks() {
    expected="pre\n"
    for ((i=0; i<$1; i++)); do
        expected=$expected"deploy\n"
    done
    expected=$expected"post"

    if ! diff "$HOOK_DIRS_TEST" <(echo -e "$expected"); then
        echo "Unexpected directory hook output!" >&2
        echo "Expected:" >&2
        echo -e "$expected" >&2
        echo "Got:" >&2
        cat "$HOOK_DIRS_TEST" >&2
        exit 1
    fi

    rm -f "$HOOK_DIRS_TEST"
    export HOOK_DIRS_TEST="$(mktemp)"
}

common_no_force_renew() {
    certbot_test_no_force_renew \
        --authenticator standalone \
        --installer null \
        "$@"
}

common() {
    common_no_force_renew \
        --renew-by-default \
        "$@"
}

export HOOK_TEST="/tmp/hook$$"
CheckHooks() {
    if [ $(head -n1 "$HOOK_TEST") = "wtf.pre" ]; then
        expected="wtf.pre\ndeploy\n"
        if [ $(sed '3q;d' "$HOOK_TEST") = "deploy" ]; then
            expected=$expected"deploy\nwtf2.pre\n"
        else
            expected=$expected"wtf2.pre\ndeploy\n"
        fi
        expected=$expected"deploy\ndeploy\nwtf.post\nwtf2.post"
    else
        expected="wtf2.pre\ndeploy\n"
        if [ $(sed '3q;d' "$HOOK_TEST") = "deploy" ]; then
            expected=$expected"deploy\nwtf.pre\n"
        else
            expected=$expected"wtf.pre\ndeploy\n"
        fi
        expected=$expected"deploy\ndeploy\nwtf2.post\nwtf.post"
    fi

    if ! cmp --quiet <(echo -e "$expected") "$HOOK_TEST" ; then
        echo Hooks did not run as expected\; got >&2
        cat "$HOOK_TEST" >&2
        echo -e "Expected\n$expected" >&2
        rm "$HOOK_TEST"
        exit 1
    fi
    rm "$HOOK_TEST"
}

# Checks if deploy is in the hook output and deletes the file
DeployInHookOutput() {
    CONTENTS=$(cat "$HOOK_TEST")
    rm "$HOOK_TEST"
    grep deploy <(echo "$CONTENTS")
}

# Asserts that there is a saved renew_hook for a lineage.
#
# Arguments:
#     Name of lineage to check
CheckSavedRenewHook() {
    if ! grep renew_hook "$config_dir/renewal/$1.conf"; then
        echo "Hook wasn't saved as renew_hook" >&2
        exit 1
    fi
}

# Asserts the deploy hook was properly run and saved and deletes the hook file
#
# Arguments:
#   Lineage name of the issued cert
CheckDeployHook() {
    if ! DeployInHookOutput; then
        echo "The deploy hook wasn't run" >&2
        exit 1
    fi
    CheckSavedRenewHook $1
}

# Asserts the renew hook wasn't run but was saved and deletes the hook file
#
# Arguments:
#   Lineage name of the issued cert
# Asserts the deploy hook wasn't run and deletes the hook file
CheckRenewHook() {
    if DeployInHookOutput; then
        echo "The renew hook was incorrectly run" >&2
        exit 1
    fi
    CheckSavedRenewHook $1
}

# Cleanup coverage data
coverage erase

# test for regressions of #4719
get_num_tmp_files() {
    ls -1 /tmp | wc -l
}
num_tmp_files=$(get_num_tmp_files)
common --csr / && echo expected error && exit 1 || true
common --help
common --help all
common --version
if [ $(get_num_tmp_files) -ne $num_tmp_files ]; then
    echo "New files or directories created in /tmp!"
    exit 1
fi
CreateDirHooks

common register
for dir in $renewal_hooks_dirs; do
    if [ ! -d "$dir" ]; then
        echo "Hook directory not created by Certbot!" >&2
        exit 1
    fi
done
common register --update-registration --email example@example.org

common plugins --init --prepare | grep webroot

# We start a server listening on the port for the
# unrequested challenge to prevent regressions in #3601.
python ./tests/run_http_server.py $http_01_port &
python_server_pid=$!

certname="le1.wtf"
common --domains le1.wtf --preferred-challenges tls-sni-01 auth \
       --cert-name $certname \
       --pre-hook 'echo wtf.pre >> "$HOOK_TEST"' \
       --post-hook 'echo wtf.post >> "$HOOK_TEST"'\
       --deploy-hook 'echo deploy >> "$HOOK_TEST"'
kill $python_server_pid
CheckDeployHook $certname

python ./tests/run_http_server.py $tls_sni_01_port &
python_server_pid=$!
certname="le2.wtf"
common --domains le2.wtf --preferred-challenges http-01 run \
       --cert-name $certname \
       --pre-hook 'echo wtf.pre >> "$HOOK_TEST"' \
       --post-hook 'echo wtf.post >> "$HOOK_TEST"'\
       --deploy-hook 'echo deploy >> "$HOOK_TEST"'
kill $python_server_pid
CheckDeployHook $certname

certname="le.wtf"
common certonly -a manual -d le.wtf --rsa-key-size 4096 --cert-name $certname \
    --manual-auth-hook ./tests/manual-http-auth.sh \
    --manual-cleanup-hook ./tests/manual-http-cleanup.sh \
    --pre-hook 'echo wtf2.pre >> "$HOOK_TEST"' \
    --post-hook 'echo wtf2.post >> "$HOOK_TEST"' \
    --renew-hook 'echo deploy >> "$HOOK_TEST"'
CheckRenewHook $certname

certname="dns.le.wtf"
common -a manual -d dns.le.wtf --preferred-challenges dns,tls-sni run \
    --cert-name $certname \
    --manual-auth-hook ./tests/manual-dns-auth.sh \
    --pre-hook 'echo wtf2.pre >> "$HOOK_TEST"' \
    --post-hook 'echo wtf2.post >> "$HOOK_TEST"' \
    --renew-hook 'echo deploy >> "$HOOK_TEST"'
CheckRenewHook $certname

common certonly --cert-name newname -d newname.le.wtf

export CSR_PATH="${root}/csr.der" KEY_PATH="${root}/key.pem" \
       OPENSSL_CNF=examples/openssl.cnf
./examples/generate-csr.sh le3.wtf
common auth --csr "$CSR_PATH" \
       --cert-path "${root}/csr/cert.pem" \
       --chain-path "${root}/csr/chain.pem"
openssl x509 -in "${root}/csr/cert.pem" -text
openssl x509 -in "${root}/csr/chain.pem" -text

common --domains le3.wtf install \
       --cert-path "${root}/csr/cert.pem" \
       --key-path "${root}/csr/key.pem"

CheckCertCount() {
    CERTCOUNT=`ls "${root}/conf/archive/$1/cert"* | wc -l`
    if [ "$CERTCOUNT" -ne "$2" ] ; then
        echo Wrong cert count, not "$2" `ls "${root}/conf/archive/$1/"*`
        exit 1
    fi
}

CheckCertCount "le.wtf" 1
# This won't renew (because it's not time yet)
common_no_force_renew renew
CheckCertCount "le.wtf" 1
if [ -s "$HOOK_DIRS_TEST" ]; then
    echo "Directory hooks were executed for non-renewal!" >&2;
    exit 1
fi

rm -rf "$renewal_hooks_root"
# renew using HTTP manual auth hooks
common renew --cert-name le.wtf --authenticator manual
CheckCertCount "le.wtf" 2

# test renewal with no executables in hook directories
for hook_dir in $renewal_hooks_dirs; do
    touch "$hook_dir/file"
    mkdir "$hook_dir/dir"
done
# renew using DNS manual auth hooks
common renew --cert-name dns.le.wtf --authenticator manual
CheckCertCount "dns.le.wtf" 2

# test with disabled directory hooks
rm -rf "$renewal_hooks_root"
CreateDirHooks
# This will renew because the expiry is less than 10 years from now
sed -i "4arenew_before_expiry = 4 years" "$root/conf/renewal/le.wtf.conf"
common_no_force_renew renew --rsa-key-size 2048 --no-directory-hooks
CheckCertCount "le.wtf" 3
if [ -s "$HOOK_DIRS_TEST" ]; then
    echo "Directory hooks were executed with --no-directory-hooks!" >&2
    exit 1
fi

# The 4096 bit setting should persist to the first renewal, but be overridden in the second

size1=`wc -c ${root}/conf/archive/le.wtf/privkey1.pem | cut -d" " -f1`
size2=`wc -c ${root}/conf/archive/le.wtf/privkey2.pem | cut -d" " -f1`
size3=`wc -c ${root}/conf/archive/le.wtf/privkey3.pem | cut -d" " -f1`
# 4096 bit PEM keys are about ~3270 bytes, 2048 ones are about 1700 bytes
if [ "$size1" -lt 3000 ] || [ "$size2" -lt 3000 ] || [ "$size3" -gt 1800 ] ; then
    echo key sizes violate assumptions:
    ls -l "${root}/conf/archive/le.wtf/privkey"*
    exit 1
fi

# --renew-by-default is used, so renewal should occur
[ -f "$HOOK_TEST" ] && rm -f "$HOOK_TEST"
common renew
CheckCertCount "le.wtf" 4
CheckHooks
CheckDirHooks 5

# test with overlapping directory hooks on the command line
common renew --cert-name le2.wtf \
    --pre-hook "$renewal_dir_pre_hook" \
    --deploy-hook "$renewal_dir_deploy_hook" \
    --post-hook "$renewal_dir_post_hook"
CheckDirHooks 1

# test with overlapping directory hooks in the renewal conf files
common renew --cert-name le2.wtf
CheckDirHooks 1

# ECDSA
openssl ecparam -genkey -name secp384r1 -out "${root}/privkey-p384.pem"
SAN="DNS:ecdsa.le.wtf" openssl req -new -sha256 \
    -config "${OPENSSL_CNF:-openssl.cnf}" \
    -key "${root}/privkey-p384.pem" \
    -subj "/" \
    -reqexts san \
    -outform der \
    -out "${root}/csr-p384.der"
common auth --csr "${root}/csr-p384.der" \
    --cert-path "${root}/csr/cert-p384.pem" \
    --chain-path "${root}/csr/chain-p384.pem"
openssl x509 -in "${root}/csr/cert-p384.pem" -text | grep 'ASN1 OID: secp384r1'

# OCSP Must Staple
common auth --must-staple --domains "must-staple.le.wtf"
openssl x509 -in "${root}/conf/live/must-staple.le.wtf/cert.pem" -text | grep '1.3.6.1.5.5.7.1.24'

# revoke by account key
common revoke --cert-path "$root/conf/live/le.wtf/cert.pem" --delete-after-revoke
# revoke renewed
common revoke --cert-path "$root/conf/live/le1.wtf/cert.pem" --no-delete-after-revoke
if [ ! -d "$root/conf/live/le1.wtf" ]; then
    echo "cert deleted when --no-delete-after-revoke was used!"
    exit 1
fi
common delete --cert-name le1.wtf
# revoke by cert key
common revoke --cert-path "$root/conf/live/le2.wtf/cert.pem" \
    --key-path "$root/conf/live/le2.wtf/privkey.pem"

# Get new certs to test revoke with a reason, by account and by cert key
common --domains le1.wtf
common revoke --cert-path "$root/conf/live/le1.wtf/cert.pem" \
    --reason cessationOfOperation
common --domains le2.wtf
common revoke --cert-path "$root/conf/live/le2.wtf/cert.pem" \
    --key-path "$root/conf/live/le2.wtf/privkey.pem" \
    --reason keyCompromise

common unregister

out=$(common certificates)
subdomains="le dns.le newname.le must-staple.le"
for subdomain in $subdomains; do
    domain="$subdomain.wtf"
    if ! echo $out | grep "$domain"; then
        echo "$domain not in certificates output!"
        exit 1;
    fi
done

# Testing that revocation also deletes by default
subdomains="le1 le2"
for subdomain in $subdomains; do
    domain="$subdomain.wtf"
    if echo $out | grep "$domain"; then
        echo "Revoked $domain in certificates output! Should not be!"
        exit 1;
    fi
done

# Test that revocation raises correct error if --cert-name and --cert-path don't match
common --domains le1.wtf
common --domains le2.wtf
out=$(common revoke --cert-path "$root/conf/live/le1.wtf/fullchain.pem" --cert-name "le2.wtf" 2>&1) || true
if ! echo $out | grep "or both must point to the same certificate lineages."; then
    echo "Non-interactive revoking with mismatched --cert-name and --cert-path "
    echo "did not raise the correct error!"
    exit 1
fi

# Revoking by matching --cert-name and --cert-path deletes
common --domains le1.wtf
common revoke --cert-path "$root/conf/live/le1.wtf/fullchain.pem" --cert-name "le1.wtf"
out=$(common certificates)
if echo $out | grep "le1.wtf"; then
    echo "Cert le1.wtf should've been deleted! Was revoked via matching --cert-path & --cert-name"
    exit 1
fi

# Test that revocation doesn't delete if multiple lineages share an archive dir
common --domains le1.wtf
common --domains le2.wtf
sed -i "s|^archive_dir = .*$|archive_dir = $root/conf/archive/le1.wtf|" "$root/conf/renewal/le2.wtf.conf"
#common update_symlinks # not needed, but a bit more context for what this test is about
out=$(common revoke --cert-path "$root/conf/live/le1.wtf/cert.pem")
if ! echo $out | grep "Not deleting revoked certs due to overlapping archive dirs"; then
    echo "Deleted a cert that had an overlapping archive dir with another lineage!"
    exit 1
fi

cert_name="must-staple.le.wtf"
common delete --cert-name $cert_name
archive="$root/conf/archive/$cert_name"
conf="$root/conf/renewal/$cert_name.conf"
live="$root/conf/live/$cert_name"
for path in $archive $conf $live; do
    if [ -e $path ]; then
        echo "Lineage not properly deleted!"
        exit 1
    fi
done

# Most CI systems set this variable to true.
# If the tests are running as part of CI, Nginx should be available.
if ${CI:-false} || type nginx;
then
    . ./certbot-nginx/tests/boulder-integration.sh
fi

coverage report --fail-under 64 -m
