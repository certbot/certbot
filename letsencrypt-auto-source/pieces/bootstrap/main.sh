{{ bootstrap/deb_common.sh }}
{{ bootstrap/rpm_common.sh }}
{{ bootstrap/suse_common.sh }}
{{ bootstrap/arch_common.sh }}
{{ bootstrap/gentoo_common.sh }}
{{ bootstrap/free_bsd.sh }}
{{ bootstrap/mac.sh }}
{{ bootstrap/smartos.sh }}
{{ bootstrap/mageia_common.sh }}

# Install required OS packages:
Bootstrap() {
  if [ "$NO_BOOTSTRAP" = 1 ]; then
      return
  elif [ -f /etc/debian_version ]; then
    BootstrapMessage "Debian-based OSes"
    BootstrapDebCommon
  elif [ -f /etc/mageia-release ]; then
    # Mageia has both /etc/mageia-release and /etc/redhat-release
    ExperimentalBootstrap "Mageia" BootstrapMageiaCommon
  elif [ -f /etc/redhat-release ]; then
    BootstrapMessage "RedHat-based OSes"
    BootstrapRpmCommon
  elif [ -f /etc/os-release ] && `grep -q openSUSE /etc/os-release` ; then
    BootstrapMessage "openSUSE-based OSes"
    BootstrapSuseCommon
  elif [ -f /etc/arch-release ]; then
    if [ "$DEBUG" = 1 ]; then
      BootstrapMessage "Archlinux"
      BootstrapArchCommon
    else
      error "Please use pacman to install letsencrypt packages:"
      error "# pacman -S certbot certbot-apache"
      error
      error "If you would like to use the virtualenv way, please run the script again with the"
      error "--debug flag."
      exit 1
    fi
  elif [ -f /etc/manjaro-release ]; then
    ExperimentalBootstrap "Manjaro Linux" BootstrapArchCommon
  elif [ -f /etc/gentoo-release ]; then
    ExperimentalBootstrap "Gentoo" BootstrapGentooCommon
  elif uname | grep -iq FreeBSD ; then
    ExperimentalBootstrap "FreeBSD" BootstrapFreeBsd
  elif uname | grep -iq Darwin ; then
    ExperimentalBootstrap "macOS" BootstrapMac
  elif [ -f /etc/issue ] && grep -iq "Amazon Linux" /etc/issue ; then
    ExperimentalBootstrap "Amazon Linux" BootstrapRpmCommon
  elif [ -f /etc/product ] && grep -q "Joyent Instance" /etc/product ; then
    ExperimentalBootstrap "Joyent SmartOS Zone" BootstrapSmartOS
  else
    error "Sorry, I don't know how to bootstrap Certbot on your operating system!"
    error
    error "You will need to install OS dependencies, configure virtualenv, and run pip install manually."
    error "Please see https://letsencrypt.readthedocs.org/en/latest/contributing.html#prerequisites"
    error "for more info."
    exit 1
  fi
}