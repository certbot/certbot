BootstrapSuseCommon() {
  # SLE12 don't have python-virtualenv

  if [ "$ASSUME_YES" = 1 ]; then
    zypper_flags="-nq"
    install_flags="-l"
  fi

  $SUDO zypper $zypper_flags in $install_flags \
    python \
    python-devel \
    python-virtualenv \
    gcc \
    dialog \
    augeas-lenses \
    libopenssl-devel \
    libffi-devel \
    ca-certificates
}
