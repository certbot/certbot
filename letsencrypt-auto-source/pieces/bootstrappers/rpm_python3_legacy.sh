# If new packages are installed by BootstrapRpmPython3 below, this version
# number must be increased.
BOOTSTRAP_RPM_PYTHON3_LEGACY_VERSION=1

BootstrapRpmPython3Legacy() {

  InitializeRPMCommonBase

  if ! $TOOL list rh-python36 >/dev/null 2>&1; then
    echo "To use Certbot, packages from the SCL repository need to be installed."
    if ! $TOOL list centos-release-scl >/dev/null 2>&1; then
      error "Enable the SCL repository and try running Certbot again."
      exit 1
    fi
    if [ "$ASSUME_YES" = 1 ]; then
      /bin/echo -n "Enabling the SCL repository in 3 seconds..."
      sleep 1s
      /bin/echo -ne "\e[0K\rEnabling the SCL repository in 2 seconds..."
      sleep 1s
      /bin/echo -e "\e[0K\rEnabling the SCL repository in 1 second..."
      sleep 1s
    fi
    if ! $TOOL install $YES_FLAG $QUIET_FLAG centos-release-scl; then
      error "Could not enable SCL. Aborting bootstrap!"
      exit 1
    fi
  fi

  # CentOS 6 must use rh-python36 from SCL
  if $TOOL list python3-virtualenv >/dev/null 2>&1; then
    python_pkgs="rh-python36
    "
  else
    error "No supported Python package available to install. Aborting bootstrap!"
    exit 1
  fi

  # Insert the SCL specific path in PATH to resolve the correct virtualenv binary from SCL
  PATH="/opt/rh/rh-python36/root/usr/bin:$PATH"

  BootstrapRpmCommonBase "$python_pkgs"
}
