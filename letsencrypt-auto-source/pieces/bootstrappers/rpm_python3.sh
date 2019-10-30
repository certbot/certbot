# If new packages are installed by BootstrapRpmPython3 below, this version
# number must be increased.
BOOTSTRAP_RPM_PYTHON3_VERSION=1

BootstrapRpmPython3() {
  # Tested with:
  #   - Fedora 29

  InitializeRPMCommonBase

  # Fedora 29 must use python3-virtualenv
  if $TOOL list python3-virtualenv >/dev/null 2>&1; then
    python_pkgs="python3
      python3-virtualenv
      python3-devel
    "
  else
    error "No supported Python package available to install. Aborting bootstrap!"
    exit 1
  fi

  BootstrapRpmCommonBase "$python_pkgs"
}
