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

  zypper $QUIET_FLAG $zypper_flags in $install_flags \
    python \
    python-devel \
    python-virtualenv \
    gcc \
    augeas-lenses \
    libopenssl-devel \
    libffi-devel \
    ca-certificates
}
