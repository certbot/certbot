#!/bin/sh
#
# Install OS dependencies for test farm tests.

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
  sudo apt-get update || error apt-get update hit problems but continuing anyway...

  sudo apt-get install -y --no-install-recommends \
    python3 \
    python3-dev \
    python3-venv \
    gcc \
    libaugeas0 \
    libssl-dev \
    openssl \
    libffi-dev \
    ca-certificates \
    build-essential \
    curl \
    make # needed on debian 9 arm64 which doesn't have a python3 pynacl wheel

  # make sure rust isn't installed by the package manager
  if ! sudo apt-get remove -y rustc; then
    error "Could not remove existing rust. Aborting bootstrap!"
    exit 1
  fi

  # Install rust for cryptography (needed on Debian)
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  . $HOME/.cargo/env
}

# Sets TOOL to the name of the package manager
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

  InitializeRPMCommonBase

  pkgs="
    gcc
    augeas-libs
    openssl
    openssl-devel
    libffi-devel
    redhat-rpm-config
    ca-certificates
    cargo
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

  if ! sudo $TOOL install -y $pkgs; then
    error "Could not install OS dependencies. Aborting bootstrap!"
    exit 1
  fi
}

BootstrapRpmPython3() {
  InitializeRPMCommonBase

  python_pkgs="python3
    python3-devel
  "

  # We only expect this branch to be taken on RHEL 7.
  if ! sudo $TOOL list 'python3*-devel' >/dev/null 2>&1; then
    sudo yum-config-manager --enable rhel-7-server-rhui-extras-rpms rhel-7-server-rhui-optional-rpms
  fi

  BootstrapRpmCommonBase "$python_pkgs"
}

# Set Bootstrap to the function that installs OS dependencies on this system.
if [ -f /etc/debian_version ]; then
  Bootstrap() {
    BootstrapDebCommon
  }
elif [ -f /etc/redhat-release ]; then
  DeterminePythonVersion
  Bootstrap() {
    BootstrapRpmPython3
  }

fi

Bootstrap
