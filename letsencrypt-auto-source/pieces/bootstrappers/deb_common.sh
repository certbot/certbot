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

  $SUDO apt-get $QUIET_FLAG update || error apt-get update hit problems but continuing anyway...

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
  AUGVERSION=`LC_ALL=C apt-cache show --no-all-versions libaugeas0 | grep ^Version: | cut -d" " -f2`

  if [ "$ASSUME_YES" = 1 ]; then
    YES_FLAG="-y"
  fi

  AddBackportRepo() {
    # ARGS:
    BACKPORT_NAME="$1"
    BACKPORT_SOURCELINE="$2"
    say "To use the Apache Certbot plugin, augeas needs to be installed from $BACKPORT_NAME."
    if ! grep -v -e ' *#' /etc/apt/sources.list | grep -q "$BACKPORT_NAME" ; then
      # This can theoretically error if sources.list.d is empty, but in that case we don't care.
      if ! grep -v -e ' *#' /etc/apt/sources.list.d/* 2>/dev/null | grep -q "$BACKPORT_NAME"; then
        if [ "$ASSUME_YES" = 1 ]; then
          /bin/echo -n "Installing augeas from $BACKPORT_NAME in 3 seconds..."
          sleep 1s
          /bin/echo -ne "\e[0K\rInstalling augeas from $BACKPORT_NAME in 2 seconds..."
          sleep 1s
          /bin/echo -e "\e[0K\rInstalling augeas from $BACKPORT_NAME in 1 second ..."
          sleep 1s
          add_backports=1
        else
          read -p "Would you like to enable the $BACKPORT_NAME repository [Y/n]? " response
          case $response in
            [yY][eE][sS]|[yY]|"")
              add_backports=1;;
            *)
              add_backports=0;;
          esac
        fi
        if [ "$add_backports" = 1 ]; then
          $SUDO sh -c "echo $BACKPORT_SOURCELINE >> /etc/apt/sources.list.d/$BACKPORT_NAME.list"
          $SUDO apt-get $QUIET_FLAG update
        fi
      fi
    fi
    if [ "$add_backports" != 0 ]; then
      $SUDO apt-get install $QUIET_FLAG $YES_FLAG --no-install-recommends -t "$BACKPORT_NAME" $augeas_pkg
      augeas_pkg=
    fi
  }


  if dpkg --compare-versions 1.0 gt "$AUGVERSION" ; then
    if lsb_release -a | grep -q wheezy ; then
      AddBackportRepo wheezy-backports "deb http://http.debian.net/debian wheezy-backports main"
    elif lsb_release -a | grep -q precise ; then
      # XXX add ARM case
      AddBackportRepo precise-backports "deb http://archive.ubuntu.com/ubuntu precise-backports main restricted universe multiverse"
    else
      echo "No libaugeas0 version is available that's new enough to run the"
      echo "Certbot apache plugin..."
    fi
    # XXX add a case for ubuntu PPAs
  fi

  $SUDO apt-get install $QUIET_FLAG $YES_FLAG --no-install-recommends \
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
