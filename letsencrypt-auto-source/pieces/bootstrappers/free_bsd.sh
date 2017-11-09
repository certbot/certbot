# If new packages are installed by BootstrapFreeBsd below, this version number
# must be increased.
BOOTSTRAP_FREEBSD_VERSION=1

BootstrapFreeBsd() {
  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG="--quiet"
  fi

  pkg install -Ay $QUIET_FLAG \
    python \
    py27-virtualenv \
    augeas \
    libffi
}
