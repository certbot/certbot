# If new packages are installed by BootstrapDebCommon below, this version
# number must be increased.
BOOTSTRAP_DEB_COMMON_VERSION=1

BootstrapDebCommon() {
  # Current version tested with:
  #
  # - Ubuntu
  #     - 14.04 (x64)
  #     - 15.04 (x64)
  # - Debian
  #     - 7.9 "wheezy" (x64)
  #     - sid (2015-10-21) (x64)

  # Past versions tested with:
  #
  # - Debian 8.0 "jessie" (x64)
  # - Raspbian 7.8 (armhf)

  # Believed not to work:
  #
  # - Debian 6.0.10 "squeeze" (x64)

  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='-qq'
  fi

  apt-get $QUIET_FLAG update || error apt-get update hit problems but continuing anyway...

  # virtualenv binary can be found in different packages depending on
  # distro version (#346)

  virtualenv=
  # virtual env is known to apt and is installable
  if apt-cache show virtualenv > /dev/null 2>&1 ; then
    if ! LC_ALL=C apt-cache --quiet=0 show virtualenv 2>&1 | grep -q 'No packages found'; then
      virtualenv="virtualenv"
    fi
  fi

  if apt-cache show python-virtualenv > /dev/null 2>&1; then
    virtualenv="$virtualenv python-virtualenv"
  fi

  augeas_pkg="libaugeas0 augeas-lenses"

  if [ "$ASSUME_YES" = 1 ]; then
    YES_FLAG="-y"
  fi

  apt-get install $QUIET_FLAG $YES_FLAG --no-install-recommends \
    python \
    python-dev \
    $virtualenv \
    gcc \
    $augeas_pkg \
    libssl-dev \
    openssl \
    libffi-dev \
    ca-certificates \


  if ! $EXISTS virtualenv > /dev/null ; then
    error Failed to install a working \"virtualenv\" command, exiting
    exit 1
  fi
}
