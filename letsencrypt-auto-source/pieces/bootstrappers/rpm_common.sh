BootstrapRpmCommon() {
  # Tested with:
  #   - Fedora 22, 23 (x64)
  #   - Centos 7 (x64: on DigitalOcean droplet)
  #   - CentOS 7 Minimal install in a Hyper-V VM

  if type dnf 2>/dev/null
  then
    tool=dnf
  elif type yum 2>/dev/null
  then
    tool=yum

  else
    echo "Neither yum nor dnf found. Aborting bootstrap!"
    exit 1
  fi

  # Some distros and older versions of current distros use a "python27"
  # instead of "python" naming convention. Try both conventions.
  if ! $SUDO $tool install -y \
         python \
         python-devel \
         python-virtualenv \
         python-tools \
         python-pip
  then
    if ! $SUDO $tool install -y \
           python27 \
           python27-devel \
           python27-virtualenv \
           python27-tools \
           python27-pip
    then
      echo "Could not install Python dependencies. Aborting bootstrap!"
      exit 1
    fi
  fi

  if ! $SUDO $tool install -y \
         gcc \
         dialog \
         augeas-libs \
         openssl \
         openssl-devel \
         libffi-devel \
         redhat-rpm-config \
         ca-certificates
  then
      echo "Could not install additional dependencies. Aborting bootstrap!"
      exit 1
  fi


  if $SUDO $tool list installed "httpd" >/dev/null 2>&1; then
    if ! $SUDO $tool install -y mod_ssl
    then
      echo "Apache found, but mod_ssl could not be installed."
    fi
  fi
}
