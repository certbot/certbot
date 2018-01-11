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


# Most CI systems set this variable to true.
# If the tests are running as part of CI, Nginx should be available.
if ${CI:-false} || type nginx;
then
    . ./certbot-nginx/tests/boulder-integration.sh
fi

coverage report --fail-under 64 -m
