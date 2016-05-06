BootstrapGentooCommon() {
  PACKAGES="
    dev-lang/python:2.7
    dev-python/virtualenv
    dev-util/dialog
    app-admin/augeas
    dev-libs/openssl
    dev-libs/libffi
    app-misc/ca-certificates
    virtual/pkgconfig"

  case "$PACKAGE_MANAGER" in
    (paludis)
      $SUDO cave resolve --preserve-world --keep-targets if-possible $PACKAGES -x
      ;;
    (pkgcore)
      $SUDO pmerge --noreplace --oneshot $PACKAGES
      ;;
    (portage|*)
      $SUDO emerge --noreplace --oneshot $PACKAGES
      ;;
  esac
}
