# If new packages are installed by BootstrapRpmPython3 below, this version
# number must be increased.
BOOTSTRAP_RPM_PYTHON3_LEGACY_VERSION=1

# Checks if rh-python36 can be installed.
Python36SclIsAvailable() {
  InitializeRPMCommonBase >/dev/null 2>&1;

  if "${TOOL}" list rh-python36 >/dev/null 2>&1; then
    return 0
  fi
  if "${TOOL}" list centos-release-scl >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# Try to enable rh-python36 from SCL if it is necessary and possible.
EnablePython36SCL() {
  if "$EXISTS" python3.6 > /dev/null 2> /dev/null; then
      return 0
  fi
  if [ ! -f /opt/rh/rh-python36/enable ]; then
      return 0
  fi
  set +e
  if ! . /opt/rh/rh-python36/enable; then
    error 'Unable to enable rh-python36!'
    exit 1
  fi
  set -e
}

# This bootstrap concerns old RedHat-based distributions that do not ship by default
# with Python 2.7, but only Python 2.6. We bootstrap them by enabling SCL and installing
# Python 3.6. Some of these distributions are: CentOS/RHEL/OL/SL 6.
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

  # Enable SCL rh-python36 after bootstrapping.
  EnablePython36SCL
}
