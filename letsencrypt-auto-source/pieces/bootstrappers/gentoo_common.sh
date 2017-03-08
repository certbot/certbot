BootstrapGentooCommon() {
  PACKAGES="
    dev-lang/python:2.7
    dev-python/virtualenv
    app-admin/augeas
    dev-libs/openssl
    dev-libs/libffi
    app-misc/ca-certificates
    virtual/pkgconfig"

  ASK_OPTION="--ask"
  if [ "$ASSUME_YES" = 1 ]; then
    ASK_OPTION=""
  fi

  case "$PACKAGE_MANAGER" in
    (paludis)
      $SUDO cave resolve --preserve-world --keep-targets if-possible $PACKAGES -x
      ;;
    (pkgcore)
      $SUDO pmerge --noreplace --oneshot $ASK_OPTION $PACKAGES
      ;;
    (portage|*)
      $SUDO emerge --noreplace --oneshot $ASK_OPTION $PACKAGES
      ;;
  esac
}
