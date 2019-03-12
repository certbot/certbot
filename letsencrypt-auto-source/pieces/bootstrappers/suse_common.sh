# If new packages are installed by BootstrapSuseCommon below, this version
# number must be increased.
BOOTSTRAP_SUSE_COMMON_VERSION=1

BootstrapSuseCommon() {
  # SLE12 don't have python-virtualenv

  if [ "$ASSUME_YES" = 1 ]; then
    zypper_flags="-nq"
    install_flags="-l"
  fi

  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='-qq'
  fi

  if zypper search -x python-virtualenv >/dev/null 2>&1; then
    OPENSUSE_VIRTUALENV_PACKAGES="python-virtualenv"
  else
    # Since Leap 15.0 (and associated Tumbleweed version), python-virtualenv
    # is a source package, and python2-virtualenv must be used instead.
    # Also currently python2-setuptools is not a dependency of python2-virtualenv,
    # while it should be. Installing it explicitly until upstreqm fix.
    OPENSUSE_VIRTUALENV_PACKAGES="python2-virtualenv python2-setuptools"
  fi

  zypper $QUIET_FLAG $zypper_flags in $install_flags \
    python \
    python-devel \
    $OPENSUSE_VIRTUALENV_PACKAGES \
    gcc \
    augeas-lenses \
    libopenssl-devel \
    libffi-devel \
    ca-certificates
}
