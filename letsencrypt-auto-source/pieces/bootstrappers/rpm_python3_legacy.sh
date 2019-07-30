# If new packages are installed by BootstrapRpmPython3 below, this version
# number must be increased.
BOOTSTRAP_RPM_PYTHON3_LEGACY_VERSION=1

BootstrapRpmPython3Legacy() {
  # Tested with:
  #   - CentOS 6

  InitializeRPMCommonBase

  if ! "${TOOL}" list rh-python36 >/dev/null 2>&1; then
    echo "To use Certbot on this operating system, packages from the SCL repository need to be installed."
    if ! "${TOOL}" list centos-release-scl >/dev/null 2>&1; then
      error "Enable the SCL repository and try running Certbot again."
      exit 1
    fi
    if [ "${ASSUME_YES}" = 1 ]; then
      /bin/echo -n "Enabling the SCL repository in 3 seconds... (Press Ctrl-C to cancel)"
      sleep 1s
      /bin/echo -ne "\e[0K\rEnabling the SCL repository in 2 seconds... (Press Ctrl-C to cancel)"
      sleep 1s
      /bin/echo -e "\e[0K\rEnabling the SCL repository in 1 second... (Press Ctrl-C to cancel)"
      sleep 1s
    fi
    if ! "${TOOL}" install "${YES_FLAG}" "${QUIET_FLAG}" centos-release-scl; then
      error "Could not enable SCL. Aborting bootstrap!"
      exit 1
    fi
  fi

  # CentOS 6 must use rh-python36 from SCL
  if "${TOOL}" list rh-python36 >/dev/null 2>&1; then
    python_pkgs="rh-python36-python
      rh-python36-python-virtualenv
      rh-python36-python-devel
    "
  else
    error "No supported Python package available to install. Aborting bootstrap!"
    exit 1
  fi

  BootstrapRpmCommonBase "${python_pkgs}"
}
