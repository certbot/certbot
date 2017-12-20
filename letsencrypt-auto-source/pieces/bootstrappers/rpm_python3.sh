# If new packages are installed by BootstrapRpmPython3 below, this version
# number must be increased.
BOOTSTRAP_RPM_PYTHON3_VERSION=1

BootstrapRpmPython3() {
  # Tested with:
  #   - CentOS 6

  InitializeRPMCommonBase

  # EPEL uses python34
  if $TOOL list python34 >/dev/null 2>&1; then
    python_pkgs="python34
      python34-devel
      python-virtualenv
      python34-tools
      python-pip
    "
  else
    error "No support Python package available to install. Aborting bootstrap!"
    exit 1
  fi

  BootstrapRpmCommonBase "$python_pkgs"
}
