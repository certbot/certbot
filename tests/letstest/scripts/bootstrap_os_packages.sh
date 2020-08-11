#!/bin/sh
#
# Download and run the latest release version of the Certbot client.

set -e  # Work even if somebody does "sh thisscript.sh".

error() {
    echo "$@"
}

MIN_PYTHON_2_VERSION="2.7"
MIN_PYVER2=$(echo "$MIN_PYTHON_2_VERSION" | sed 's/\.//')
MIN_PYTHON_3_VERSION="3.5"
MIN_PYVER3=$(echo "$MIN_PYTHON_3_VERSION" | sed 's/\.//')
# Sets LE_PYTHON to Python version string and PYVER to the first two
# digits of the python version.
# MIN_PYVER and MIN_PYTHON_VERSION are also set by this function, and their
# values depend on if we try to use Python 3 or Python 2.
DeterminePythonVersion() {
  # Arguments: "NOCRASH" if we shouldn't crash if we don't find a good python
  #
  # If no Python is found, PYVER is set to 0.
  if [ "$USE_PYTHON_3" = 1 ]; then
    MIN_PYVER=$MIN_PYVER3
    MIN_PYTHON_VERSION=$MIN_PYTHON_3_VERSION
    for LE_PYTHON in "$LE_PYTHON" python3; do
      # Break (while keeping the LE_PYTHON value) if found.
      $EXISTS "$LE_PYTHON" > /dev/null && break
    done
  else
    MIN_PYVER=$MIN_PYVER2
    MIN_PYTHON_VERSION=$MIN_PYTHON_2_VERSION
    for LE_PYTHON in "$LE_PYTHON" python2.7 python27 python2 python; do
      # Break (while keeping the LE_PYTHON value) if found.
      $EXISTS "$LE_PYTHON" > /dev/null && break
    done
  fi
  if [ "$?" != "0" ]; then
    if [ "$1" != "NOCRASH" ]; then
      error "Cannot find any Pythons; please install one!"
      exit 1
    else
      PYVER=0
      return 0
    fi
  fi

  PYVER=$("$LE_PYTHON" -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//')
  if [ "$PYVER" -lt "$MIN_PYVER" ]; then
    if [ "$1" != "NOCRASH" ]; then
      error "You have an ancient version of Python entombed in your operating system..."
      error "This isn't going to work; you'll need at least version $MIN_PYTHON_VERSION."
      exit 1
    fi
  fi
}

BootstrapDebCommon() {
  # Current version tested with:
  #
  # - Ubuntu
  #     - 14.04 (x64)
  #     - 15.04 (x64)
  # - Debian
  #     - 7.9 "wheezy" (x64)
  #     - sid (2015-10-21) (x64)

  # Past versions tested with:
  #
  # - Debian 8.0 "jessie" (x64)
  # - Raspbian 7.8 (armhf)

  # Believed not to work:
  #
  # - Debian 6.0.10 "squeeze" (x64)

  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='-qq'
  fi

  apt-get $QUIET_FLAG update || error apt-get update hit problems but continuing anyway...

  # virtualenv binary can be found in different packages depending on
  # distro version (#346)

  virtualenv=
  # virtual env is known to apt and is installable
  if apt-cache show virtualenv > /dev/null 2>&1 ; then
    if ! LC_ALL=C apt-cache --quiet=0 show virtualenv 2>&1 | grep -q 'No packages found'; then
      virtualenv="virtualenv"
    fi
  fi

  if apt-cache show python-virtualenv > /dev/null 2>&1; then
    virtualenv="$virtualenv python-virtualenv"
  fi

  augeas_pkg="libaugeas0 augeas-lenses"

  if [ "$ASSUME_YES" = 1 ]; then
    YES_FLAG="-y"
  fi

  apt-get install $QUIET_FLAG $YES_FLAG --no-install-recommends \
    python \
    python-dev \
    $virtualenv \
    gcc \
    $augeas_pkg \
    libssl-dev \
    openssl \
    libffi-dev \
    ca-certificates \


  if ! $EXISTS virtualenv > /dev/null ; then
    error Failed to install a working \"virtualenv\" command, exiting
    exit 1
  fi
}

# If new packages are installed by BootstrapRpmCommonBase below, version
# numbers in rpm_common.sh and rpm_python3.sh must be increased.

# Sets TOOL to the name of the package manager
# Sets appropriate values for YES_FLAG and QUIET_FLAG based on $ASSUME_YES and $QUIET_FLAG.
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

  if [ "$ASSUME_YES" = 1 ]; then
    YES_FLAG="-y"
  fi
  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='--quiet'
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

  if ! $TOOL install $YES_FLAG $QUIET_FLAG $pkgs; then
    error "Could not install OS dependencies. Aborting bootstrap!"
    exit 1
  fi
}

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

# Set Bootstrap to the function that installs OS dependencies on this system.
if [ -f /etc/debian_version ]; then
  Bootstrap() {
    BootstrapMessage "Debian-based OSes"
    BootstrapDebCommon
  }
elif [ -f /etc/redhat-release ]; then
  # Run DeterminePythonVersion to decide on the basis of available Python versions
  # whether to use 2.x or 3.x on RedHat-like systems.
  # Then, revert LE_PYTHON to its previous state.
  prev_le_python="$LE_PYTHON"
  unset LE_PYTHON
  DeterminePythonVersion "NOCRASH"

  RPM_DIST_NAME=`(. /etc/os-release 2> /dev/null && echo $ID) || echo "unknown"`

  # Set RPM_DIST_VERSION to VERSION_ID from /etc/os-release after splitting on
  # '.' characters (e.g. "8.0" becomes "8"). If the command exits with an
  # error, RPM_DIST_VERSION is set to "unknown".
  RPM_DIST_VERSION=$( (. /etc/os-release 2> /dev/null && echo "$VERSION_ID") | cut -d '.' -f1 || echo "unknown")

  # If RPM_DIST_VERSION is an empty string or it contains any nonnumeric
  # characters, the value is unexpected so we set RPM_DIST_VERSION to 0.
  if [ -z "$RPM_DIST_VERSION" ] || [ -n "$(echo "$RPM_DIST_VERSION" | tr -d '[0-9]')" ]; then
     RPM_DIST_VERSION=0
  fi

  # Handle legacy RPM distributions
  if [ "$PYVER" -eq 26 ]; then
    # Check if an automated bootstrap can be achieved on this system.
    if ! Python36SclIsAvailable; then
      INTERACTIVE_BOOTSTRAP=1
    fi

    Bootstrap() {
      BootstrapMessage "Legacy RedHat-based OSes that will use Python3"
      BootstrapRpmPython3Legacy
    }
    USE_PYTHON_3=1

    # Try now to enable SCL rh-python36 for systems already bootstrapped
    # NB: EnablePython36SCL has been defined along with BootstrapRpmPython3Legacy in certbot-auto
    EnablePython36SCL
  else
    # Starting to Fedora 29, python2 is on a deprecation path. Let's move to python3 then.
    # RHEL 8 also uses python3 by default.
    if [ "$RPM_DIST_NAME" = "fedora" -a "$RPM_DIST_VERSION" -ge 29 ]; then
      RPM_USE_PYTHON_3=1
    elif [ "$RPM_DIST_NAME" = "rhel" -a "$RPM_DIST_VERSION" -ge 8 ]; then
      RPM_USE_PYTHON_3=1
    elif [ "$RPM_DIST_NAME" = "centos" -a "$RPM_DIST_VERSION" -ge 8 ]; then
      RPM_USE_PYTHON_3=1
    else
      RPM_USE_PYTHON_3=0
    fi

    if [ "$RPM_USE_PYTHON_3" = 1 ]; then
      Bootstrap() {
        BootstrapMessage "RedHat-based OSes that will use Python3"
        BootstrapRpmPython3
      }
      USE_PYTHON_3=1
    else
      Bootstrap() {
        BootstrapMessage "RedHat-based OSes"
        BootstrapRpmCommon
      }
    fi
  fi

  LE_PYTHON="$prev_le_python"
fi

Bootstrap
