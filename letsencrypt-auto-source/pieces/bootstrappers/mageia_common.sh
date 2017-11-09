# If new packages are installed by BootstrapMageiaCommon below, this version
# number must be increased.
BOOTSTRAP_MAGEIA_COMMON_VERSION=1

BootstrapMageiaCommon() {
  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='--quiet'
  fi

  if ! urpmi --force $QUIET_FLAG \
      python \
      libpython-devel \
      python-virtualenv
    then
      error "Could not install Python dependencies. Aborting bootstrap!"
      exit 1
  fi

  if ! urpmi --force $QUIET_FLAG \
      git \
      gcc \
      python-augeas \
      libopenssl-devel \
      libffi-devel \
      rootcerts
    then
      error "Could not install additional dependencies. Aborting bootstrap!"
      exit 1
    fi
}
