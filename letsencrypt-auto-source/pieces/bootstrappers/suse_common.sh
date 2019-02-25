# If new packages are installed by BootstrapSuseCommon below, this version
# number must be increased.
BOOTSTRAP_SUSE_COMMON_VERSION=2

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
    PYTHON_OPENSUSE_PACKAGES="python python-devel python-virtualenv"
  else
    # Since Leap 15.0 (and associated Tumbleweed version), python-virtualenv
    # is a source package, and python2-virtualenv must be used instead.
    PYTHON_OPENSUSE_PACKAGES="python2 python2-devel python2-virtualenv"
  fi

  zypper $QUIET_FLAG $zypper_flags in $install_flags \
    $PYTHON_OPENSUSE_PACKAGES \
    gcc \
    augeas-lenses \
    libopenssl-devel \
    libffi-devel \
    ca-certificates
}
