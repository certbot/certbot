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

# Check that python executable is available in the PATH. Fail immediatly if not.
command -v python > /dev/null || (echo "Error, python executable is not in the PATH" && exit 1)

. ./tests/integration/_common.sh
export PATH="$PATH:/usr/sbin"  # /usr/sbin/nginx
CURRENT_DIR="$(pwd)"

cleanup_and_exit() {
    EXIT_STATUS=$?
    cd $CURRENT_DIR
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

# Return success only if input contains exactly $1 lines of text, of
# which $2 different values occur in the first field.
TotalAndDistinctLines() {
    total=$1
    distinct=$2
    awk '{a[$1] = 1}; END {n = 0; for (i in a) { n++ }; exit(NR !='$total' || n !='$distinct')}'
}

# Cleanup coverage data
coverage erase

# test for regressions of #4719
get_num_tmp_files() {
    ls -1 /tmp | wc -l
}
num_tmp_files=$(get_num_tmp_files)
common --csr / > /dev/null && echo expected error && exit 1 || true
common --help > /dev/null
common --help all > /dev/null
common --version > /dev/null
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

common unregister

common register --email ex1@domain.org,ex2@domain.org

# TODO: When `certbot register --update-registration` is fully deprecated, delete the two following deprecated uses

common register --update-registration --email ex1@domain.org

common register --update-registration --email ex1@domain.org,ex2@domain.org

common update_account --email example@domain.org

common update_account --email ex1@domain.org,ex2@domain.org

common plugins --init --prepare | grep webroot

# We start a server listening on the port for the
# unrequested challenge to prevent regressions in #3601.
python ./tests/run_http_server.py $https_port &
python_server_pid=$!
certname="le1.wtf"
common --domains le1.wtf --preferred-challenges http-01 auth \
       --cert-name $certname \
       --pre-hook 'echo wtf.pre >> "$HOOK_TEST"' \
       --post-hook 'echo wtf.post >> "$HOOK_TEST"'\
       --deploy-hook 'echo deploy >> "$HOOK_TEST"'
CheckDeployHook $certname

# Previous test used to be a tls-sni-01 challenge that is not supported anymore.
# Now it is a http-01 challenge and this makes it a duplicate of the following test.
# But removing it would break many tests here, as they are strongly coupled.
# See https://github.com/certbot/certbot/pull/6852
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
common -a manual -d dns.le.wtf --preferred-challenges dns run \
    --cert-name $certname \
    --manual-auth-hook ./tests/manual-dns-auth.sh \
    --manual-cleanup-hook ./tests/manual-dns-cleanup.sh \
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
       --key-path "${root}/key.pem"

CheckCertCount() {
    CERTCOUNT=`ls "${root}/conf/archive/$1/cert"* | wc -l`
    if [ "$CERTCOUNT" -ne "$2" ] ; then
        echo Wrong cert count, not "$2" `ls "${root}/conf/archive/$1/"*`
        exit 1
    fi
}

CheckPermissions() {
# Args: <filepath_1> <filepath_2> <mask>
# Checks mode of two files match under <mask>
    masked_mode() { echo $((0`stat -c %a $1` & 0$2)); }
    if [ `masked_mode $1 $3` -ne `masked_mode $2 $3` ] ; then
        echo "With $3 mask, expected mode `masked_mode $1 $3`, got `masked_mode $2 $3` on file $2"
        exit 1
    fi
}

CheckGID() {
# Args: <filepath_1> <filepath_2>
# Checks group owner of two files match
    group_owner() { echo `stat -c %G $1`; }
    if [ `group_owner $1` != `group_owner $2` ] ; then
        echo "Expected group owner `group_owner $1`, got `group_owner $2` on file $2"
        exit 1
    fi
}

CheckOthersPermission() {
# Args: <filepath_1> <expected mode>
# Tests file's other/world permission against expected mode
    other_permission=$((0`stat -c %a $1` & 07))
    if [ $other_permission -ne $2 ] ; then
        echo "Expected file $1 to have others mode $2, got $other_permission instead"
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

CheckOthersPermission "${root}/conf/archive/le.wtf/privkey1.pem" 0
CheckOthersPermission "${root}/conf/archive/le.wtf/privkey2.pem" 0
CheckPermissions "${root}/conf/archive/le.wtf/privkey1.pem" "${root}/conf/archive/le.wtf/privkey2.pem" 074
CheckGID "${root}/conf/archive/le.wtf/privkey1.pem" "${root}/conf/archive/le.wtf/privkey2.pem"
chmod 0444 "${root}/conf/archive/le.wtf/privkey2.pem"

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
CheckGID "${root}/conf/archive/le.wtf/privkey2.pem" "${root}/conf/archive/le.wtf/privkey3.pem"
CheckPermissions "${root}/conf/archive/le.wtf/privkey2.pem" "${root}/conf/archive/le.wtf/privkey3.pem" 074
CheckOthersPermission "${root}/conf/archive/le.wtf/privkey3.pem" 04

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

# manual-dns-auth.sh will skip completing the challenge for domains that begin
# with fail.
common -a manual -d dns1.le.wtf,fail.dns1.le.wtf \
    --allow-subset-of-names \
    --preferred-challenges dns \
    --manual-auth-hook ./tests/manual-dns-auth.sh \
    --manual-cleanup-hook ./tests/manual-dns-cleanup.sh

if common certificates | grep "fail\.dns1\.le\.wtf"; then
    echo "certificate should not have been issued for domain!" >&2
    exit 1
fi

# reuse-key
common --domains reusekey.le.wtf --reuse-key
common renew --cert-name reusekey.le.wtf
CheckCertCount "reusekey.le.wtf" 2
ls -l "${root}/conf/archive/reusekey.le.wtf/privkey"*
# The final awk command here exits successfully if its input consists of
# exactly two lines with identical first fields, and unsuccessfully otherwise.
sha256sum "${root}/conf/archive/reusekey.le.wtf/privkey"* | TotalAndDistinctLines 2 1

# don't reuse key (just by forcing reissuance without --reuse-key)
common --cert-name reusekey.le.wtf --domains reusekey.le.wtf --force-renewal
CheckCertCount "reusekey.le.wtf" 3
ls -l "${root}/conf/archive/reusekey.le.wtf/privkey"*
# Exactly three lines, of which exactly two identical first fields.
sha256sum "${root}/conf/archive/reusekey.le.wtf/privkey"* | TotalAndDistinctLines 3 2

# Nonetheless, all three certificates are different even though two of them
# share the same subject key.
sha256sum "${root}/conf/archive/reusekey.le.wtf/cert"* | TotalAndDistinctLines 3 3

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
openssl x509 -in "${root}/conf/live/must-staple.le.wtf/cert.pem" -text | grep -E 'status_request|1\.3\.6\.1\.5\.5\.7\.1\.24'

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

# Test that revocation raises correct error when both --cert-name and --cert-path specified
common --domains le1.wtf
out=$(common revoke --cert-path "$root/conf/live/le1.wtf/fullchain.pem" --cert-name "le1.wtf" 2>&1) || true
if ! echo $out | grep "Exactly one of --cert-path or --cert-name must be specified"; then
    echo "Non-interactive revoking with both --cert-name and --cert-path "
    echo "did not raise the correct error!"
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

# Test ACMEv2-only features
if [ "${BOULDER_INTEGRATION:-v1}" = "v2" ]; then
    common -a manual -d '*.le4.wtf,le4.wtf' --preferred-challenges dns \
        --manual-auth-hook ./tests/manual-dns-auth.sh \
        --manual-cleanup-hook ./tests/manual-dns-cleanup.sh
fi

# Test OCSP status

## OCSP 1: Check stale OCSP status
pushd ./tests/integration

OUT=`common certificates --config-dir sample-config`
TEST_CERTS=`echo "$OUT" | grep TEST_CERT | wc -l`
EXPIRED=`echo "$OUT" | grep EXPIRED | wc -l`

if [ "$TEST_CERTS" != 2 ] ; then
    echo "Did not find two test certs as expected ($TEST_CERTS)"
    exit 1
fi

if [ "$EXPIRED" != 2 ] ; then
    echo "Did not find two test certs as expected ($EXPIRED)"
    exit 1
fi

popd

## OSCP 2: Check live certificate OCSP status (VALID)
common --domains le-ocsp-check.wtf
OUT=`common certificates`
VALID=`echo $OUT | grep 'Domains: le-ocsp-check.wtf' -A 1 | grep VALID | wc -l`
EXPIRED=`echo $OUT | grep 'Domains: le-ocsp-check.wtf' -A 1 | grep EXPIRED | wc -l`

if [ "$VALID" != 1 ] ; then
    echo "Expected le-ocsp-check.wtf to be VALID"
    exit 1
fi

if [ "$EXPIRED" != 0 ] ; then
    echo "Did not expect le-ocsp-check.wtf to be EXPIRED"
    exit 1
fi

## OSCP 3: Check live certificate OCSP status (REVOKED)
common revoke --cert-name le-ocsp-check.wtf --no-delete-after-revoke
OUT=`common certificates`
INVALID=`echo $OUT | grep 'Domains: le-ocsp-check.wtf' -A 1 | grep INVALID | wc -l`
REVOKED=`echo $OUT | grep 'Domains: le-ocsp-check.wtf' -A 1 | grep REVOKED | wc -l`

if [ "$INVALID" != 1 ] ; then
    echo "Expected le-ocsp-check.wtf to be INVALID"
    exit 1
fi

if [ "$REVOKED" != 1 ] ; then
    echo "Expected le-ocsp-check.wtf to be REVOKED"
    exit 1
fi

coverage report --fail-under 64 --include 'certbot/*' --show-missing
