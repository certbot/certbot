#!/bin/sh
#
# Download and run the latest release version of the Certbot client.

set -ex  # Work even if somebody does "sh thisscript.sh".

error() {
    echo "$@"
}

if command -v command > /dev/null 2>&1 ; then
  export EXISTS="command -v"
elif which which > /dev/null 2>&1 ; then
  export EXISTS="which"
else
  error "Cannot find command nor which... please install one!"
  exit 1
fi

# Sets LE_PYTHON to Python version string and PYVER to the first two
# digits of the python version.
DeterminePythonVersion() {
  # If no Python is found, PYVER is set to 0.
  for LE_PYTHON in python3 python2.7 python27 python2 python; do
    # Break (while keeping the LE_PYTHON value) if found.
    $EXISTS "$LE_PYTHON" > /dev/null && break
  done
  if [ "$?" != "0" ]; then
    PYVER=0
    return 0
  fi

  PYVER=$("$LE_PYTHON" -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//')
}

BootstrapDebCommon() {
  apt-get update || error apt-get update hit problems but continuing anyway...

  apt-get install -y --no-install-recommends \
    python3 \
    python3-dev \
    python3-venv \
    gcc \
    libaugeas0 \
    libssl-dev \
    openssl \
    libffi-dev \
    ca-certificates \
    make # needed on debian 9 arm64 which doesn't have a python3 pynacl wheel

}

# If new packages are installed by BootstrapRpmCommonBase below, version
# numbers in rpm_common.sh and rpm_python3.sh must be increased.

# Sets TOOL to the name of the package manager
# Note: this function is called both while selecting the bootstrap scripts and
# during the actual bootstrap. Some things like prompting to user can be done in the latter
# case, but not in the former one.
InitializeRPMCommonBase() {
  if type dnf 2>/dev/null
  then
    TOOL=dnf
  elif type yum 2>/dev/null
  then
    TOOL=yum

  else
    error "Neither yum nor dnf found. Aborting bootstrap!"
    exit 1
  fi

}

BootstrapRpmCommonBase() {
  # Arguments: whitespace-delimited python packages to install

  InitializeRPMCommonBase # This call is superfluous in practice

  pkgs="
    gcc
    augeas-libs
    openssl
    openssl-devel
    libffi-devel
    redhat-rpm-config
    ca-certificates
  "

  # Add the python packages
  pkgs="$pkgs
    $1
  "

  if $TOOL list installed "httpd" >/dev/null 2>&1; then
    pkgs="$pkgs
      mod_ssl
    "
  fi

  if ! $TOOL install -y $pkgs; then
    error "Could not install OS dependencies. Aborting bootstrap!"
    exit 1
  fi
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
    if ! "${TOOL}" install -y centos-release-scl; then
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

BootstrapRpmPython3() {
  InitializeRPMCommonBase

  python_pkgs="python3
    python3-devel
    python3-devel.x86_64
  "

  BootstrapRpmCommonBase "$python_pkgs"
}

# Set Bootstrap to the function that installs OS dependencies on this system.
if [ -f /etc/debian_version ]; then
  Bootstrap() {
    BootstrapDebCommon
  }
elif [ -f /etc/redhat-release ]; then
  DeterminePythonVersion
  # Handle legacy RPM distributions
  if [ "$PYVER" -eq 26 ]; then
    Bootstrap() {
      BootstrapRpmPython3Legacy
    }
    # Try now to enable SCL rh-python36 for systems already bootstrapped
    # NB: EnablePython36SCL has been defined along with BootstrapRpmPython3Legacy in certbot-auto
    EnablePython36SCL
  else
    Bootstrap() {
      BootstrapRpmPython3
    }
  fi

fi

Bootstrap
