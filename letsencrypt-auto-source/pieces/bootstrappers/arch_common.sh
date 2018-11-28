# If new packages are installed by BootstrapArchCommon below, this version
# number must be increased.
BOOTSTRAP_ARCH_COMMON_VERSION=1

BootstrapArchCommon() {
  # Tested with:
  #   - ArchLinux (x86_64)
  #
  # "python-virtualenv" is Python3, but "python2-virtualenv" provides
  # only "virtualenv2" binary, not "virtualenv".

  deps="
    python2
    python-virtualenv
    gcc
    augeas
    openssl
    libffi
    ca-certificates
    pkg-config
  "

  # pacman -T exits with 127 if there are missing dependencies
  missing=$(pacman -T $deps) || true

  if [ "$ASSUME_YES" = 1 ]; then
    noconfirm="--noconfirm"
  fi

  if [ "$missing" ]; then
    if [ "$QUIET" = 1 ]; then
      pacman -S --needed $missing $noconfirm > /dev/null
    else
      pacman -S --needed $missing $noconfirm
    fi
  fi
}
