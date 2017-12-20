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
  fi
  # TODO: add some elifs and elses for other distros that
  # might have 2.6 or no python installed to get here

  BootstrapRpmCommonBase "$python_pkgs"
}
