# If new packages are installed by BootstrapRpmPython3 below, this version
# number must be increased.
BOOTSTRAP_RPM_PYTHON3_VERSION=1

BootstrapRpmPython3() {
  # Tested with:
  #   - CentOS 6 (EPEL must be installed manually)
  # EPEL uses python34
  python_pkgs="python34
    python34-devel
    python-virtualenv
    python34-tools
    python-pip
  "
  BootstrapRpmCommonBase $python_pkgs
}