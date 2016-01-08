BootstrapArchCommon() {
  # Tested with:
  #   - ArchLinux (x86_64)
  #
  # "python-virtualenv" is Python3, but "python2-virtualenv" provides
  # only "virtualenv2" binary, not "virtualenv" necessary in
  # ./bootstrap/dev/_common_venv.sh

  deps="
    python2
    python-virtualenv
    gcc
    dialog
    augeas
    openssl
    libffi
    ca-certificates
    pkg-config
  "

  missing=$("$SUDO" pacman -T $deps)

  if [ "$missing" ]; then
    "$SUDO" pacman -S --needed $missing
  fi
}
