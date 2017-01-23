BootstrapMageiaCommon() {
  if [ "$QUIET" == 1 ]; then
    QUIET_FLAG='--quiet'
  fi

  if ! $SUDO urpmi --force $QUIET_FLAG \
      python \
      libpython-devel \
      python-virtualenv
    then
      echo "Could not install Python dependencies. Aborting bootstrap!"
      exit 1
  fi

  if ! $SUDO urpmi --force $QUIET_FLAG \
      git \
      gcc \
      python-augeas \
      libopenssl-devel \
      libffi-devel \
      rootcerts
    then
      echo "Could not install additional dependencies. Aborting bootstrap!"
      exit 1
    fi
}
