# If new packages are installed by BootstrapRpmCommon below, this version
# number must be increased.
BOOTSTRAP_RPM_COMMON_VERSION=1

BootstrapRpmCommon() {
  # Tested with:
  #   - Fedora 20, 21, 22, 23 (x64)
  #   - Centos 7 (x64: on DigitalOcean droplet)
  #   - CentOS 7 Minimal install in a Hyper-V VM
  #   - CentOS 6

  InitializeRPMCommonBase

  # Most RPM distros use the "python" or "python-" naming convention.  Let's try that first.
  if $TOOL list python >/dev/null 2>&1; then
    python_pkgs="$python
      python-devel
      python-virtualenv
      python-tools
      python-pip
    "
  # Fedora 26 starts to use the prefix python2 for python2 based packages.
  # this elseif is theoretically for any Fedora over version 26:
  elif $TOOL list python2 >/dev/null 2>&1; then
    python_pkgs="$python2
      python2-libs
      python2-setuptools
      python2-devel
      python2-virtualenv
      python2-tools
      python2-pip
    "
  # Some distros and older versions of current distros use a "python27"
  # instead of the "python" or "python-" naming convention.
  else
    python_pkgs="$python27
      python27-devel
      python27-virtualenv
      python27-tools
      python27-pip
    "
  fi

  BootstrapRpmCommonBase "$python_pkgs"
}
