#!/bin/sh
#
# Download and run the latest release version of the Certbot client.
#
# NOTE: THIS SCRIPT IS AUTO-GENERATED AND SELF-UPDATING
#
# IF YOU WANT TO EDIT IT LOCALLY, *ALWAYS* RUN YOUR COPY WITH THE
# "--no-self-upgrade" FLAG
#
# IF YOU WANT TO SEND PULL REQUESTS, THE REAL SOURCE FOR THIS FILE IS
# letsencrypt-auto-source/letsencrypt-auto.template AND
# letsencrypt-auto-source/pieces/bootstrappers/*

set -e  # Work even if somebody does "sh thisscript.sh".

# Note: you can set XDG_DATA_HOME or VENV_PATH before running this script,
# if you want to change where the virtual environment will be installed
XDG_DATA_HOME=${XDG_DATA_HOME:-~/.local/share}
VENV_NAME="letsencrypt"
VENV_PATH=${VENV_PATH:-"$XDG_DATA_HOME/$VENV_NAME"}
VENV_BIN="$VENV_PATH/bin"
LE_AUTO_VERSION="0.9.3"
BASENAME=$(basename $0)
USAGE="Usage: $BASENAME [OPTIONS]
A self-updating wrapper script for the Certbot ACME client. When run, updates
to both this script and certbot will be downloaded and installed. After
ensuring you have the latest versions installed, certbot will be invoked with
all arguments you have provided.

Help for certbot itself cannot be provided until it is installed.

  --debug                                   attempt experimental installation
  -h, --help                                print this help
  -n, --non-interactive, --noninteractive   run without asking for user input
  --no-self-upgrade                         do not download updates
  --os-packages-only                        install OS dependencies and exit
  -q, --quiet                               provide only update/error output
  -v, --verbose                             provide more output

All arguments are accepted and forwarded to the Certbot client when run."

for arg in "$@" ; do
  case "$arg" in
    --debug)
      DEBUG=1;;
    --os-packages-only)
      OS_PACKAGES_ONLY=1;;
    --no-self-upgrade)
      # Do not upgrade this script (also prevents client upgrades, because each
      # copy of the script pins a hash of the python client)
      NO_SELF_UPGRADE=1;;
    --help)
      HELP=1;;
    --noninteractive|--non-interactive)
      ASSUME_YES=1;;
    --quiet)
      QUIET=1;;
    --verbose)
      VERBOSE=1;;
    -[!-]*)
      while getopts ":hnvq" short_arg $arg; do
        case "$short_arg" in
          h)
            HELP=1;;
          n)
            ASSUME_YES=1;;
          q)
            QUIET=1;;
          v)
            VERBOSE=1;;
        esac
      done;;
  esac
done

if [ $BASENAME = "letsencrypt-auto" ]; then
  # letsencrypt-auto does not respect --help or --yes for backwards compatibility
  ASSUME_YES=1
  HELP=0
fi

# certbot-auto needs root access to bootstrap OS dependencies, and
# certbot itself needs root access for almost all modes of operation
# The "normal" case is that sudo is used for the steps that need root, but
# this script *can* be run as root (not recommended), or fall back to using
# `su`
SUDO_ENV=""
export CERTBOT_AUTO="$0"
if test "`id -u`" -ne "0" ; then
  if command -v sudo 1>/dev/null 2>&1; then
    SUDO=sudo
    SUDO_ENV="CERTBOT_AUTO=$0"
  else
    echo \"sudo\" is not available, will use \"su\" for installation steps...
    # Because the parameters in `su -c` has to be a string,
    # we need properly escape it
    su_sudo() {
      args=""
      # This `while` loop iterates over all parameters given to this function.
      # For each parameter, all `'` will be replace by `'"'"'`, and the escaped string
      # will be wrapped in a pair of `'`, then appended to `$args` string
      # For example, `echo "It's only 1\$\!"` will be escaped to:
      #   'echo' 'It'"'"'s only 1$!'
      #     │       │└┼┘│
      #     │       │ │ └── `'s only 1$!'` the literal string
      #     │       │ └── `\"'\"` is a single quote (as a string)
      #     │       └── `'It'`, to be concatenated with the strings following it
      #     └── `echo` wrapped in a pair of `'`, it's totally fine for the shell command itself
      while [ $# -ne 0 ]; do
        args="$args'$(printf "%s" "$1" | sed -e "s/'/'\"'\"'/g")' "
        shift
      done
      su root -c "$args"
    }
    SUDO=su_sudo
  fi
else
  SUDO=
fi

ExperimentalBootstrap() {
  # Arguments: Platform name, bootstrap function name
  if [ "$DEBUG" = 1 ]; then
    if [ "$2" != "" ]; then
      echo "Bootstrapping dependencies via $1..."
      $2
    fi
  else
    echo "FATAL: $1 support is very experimental at present..."
    echo "if you would like to work on improving it, please ensure you have backups"
    echo "and then run this script again with the --debug flag!"
    exit 1
  fi
}

DeterminePythonVersion() {
  for LE_PYTHON in "$LE_PYTHON" python2.7 python27 python2 python; do
    # Break (while keeping the LE_PYTHON value) if found.
    command -v "$LE_PYTHON" > /dev/null && break
  done
  if [ "$?" != "0" ]; then
    echo "Cannot find any Pythons; please install one!"
    exit 1
  fi
  export LE_PYTHON

  PYVER=`"$LE_PYTHON" -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`
  if [ "$PYVER" -lt 26 ]; then
    echo "You have an ancient version of Python entombed in your operating system..."
    echo "This isn't going to work; you'll need at least version 2.6."
    exit 1
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

  $SUDO apt-get update || echo apt-get update hit problems but continuing anyway...

  # virtualenv binary can be found in different packages depending on
  # distro version (#346)

  virtualenv=
  if apt-cache show virtualenv > /dev/null 2>&1 && ! apt-cache --quiet=0 show virtualenv 2>&1 | grep -q 'No packages found'; then
    virtualenv="virtualenv"
  fi

  if apt-cache show python-virtualenv > /dev/null 2>&1; then
    virtualenv="$virtualenv python-virtualenv"
  fi

  augeas_pkg="libaugeas0 augeas-lenses"
  AUGVERSION=`apt-cache show --no-all-versions libaugeas0 | grep ^Version: | cut -d" " -f2`

  if [ "$ASSUME_YES" = 1 ]; then
    YES_FLAG="-y"
  fi

  AddBackportRepo() {
      # ARGS:
      BACKPORT_NAME="$1"
      BACKPORT_SOURCELINE="$2"
      echo "To use the Apache Certbot plugin, augeas needs to be installed from $BACKPORT_NAME."
      if ! grep -v -e ' *#' /etc/apt/sources.list | grep -q "$BACKPORT_NAME" ; then
          # This can theoretically error if sources.list.d is empty, but in that case we don't care.
          if ! grep -v -e ' *#' /etc/apt/sources.list.d/* 2>/dev/null | grep -q "$BACKPORT_NAME"; then
              if [ "$ASSUME_YES" = 1 ]; then
                  /bin/echo -n "Installing augeas from $BACKPORT_NAME in 3 seconds..."
                  sleep 1s
                  /bin/echo -ne "\e[0K\rInstalling augeas from $BACKPORT_NAME in 2 seconds..."
                  sleep 1s
                  /bin/echo -e "\e[0K\rInstalling augeas from $BACKPORT_NAME in 1 second ..."
                  sleep 1s
                  add_backports=1
              else
                  read -p "Would you like to enable the $BACKPORT_NAME repository [Y/n]? " response
                  case $response in
                      [yY][eE][sS]|[yY]|"")
                          add_backports=1;;
                      *)
                          add_backports=0;;
                  esac
              fi
              if [ "$add_backports" = 1 ]; then
                  $SUDO sh -c "echo $BACKPORT_SOURCELINE >> /etc/apt/sources.list.d/$BACKPORT_NAME.list"
                  $SUDO apt-get update
              fi
          fi
      fi
      if [ "$add_backports" != 0 ]; then
          $SUDO apt-get install $YES_FLAG --no-install-recommends -t "$BACKPORT_NAME" $augeas_pkg
          augeas_pkg=
      fi
  }


  if dpkg --compare-versions 1.0 gt "$AUGVERSION" ; then
      if lsb_release -a | grep -q wheezy ; then
          AddBackportRepo wheezy-backports "deb http://http.debian.net/debian wheezy-backports main"
      elif lsb_release -a | grep -q precise ; then
          # XXX add ARM case
          AddBackportRepo precise-backports "deb http://archive.ubuntu.com/ubuntu precise-backports main restricted universe multiverse"
      else
          echo "No libaugeas0 version is available that's new enough to run the"
          echo "Certbot apache plugin..."
      fi
      # XXX add a case for ubuntu PPAs
  fi

  $SUDO apt-get install $YES_FLAG --no-install-recommends \
    python \
    python-dev \
    $virtualenv \
    gcc \
    dialog \
    $augeas_pkg \
    libssl-dev \
    libffi-dev \
    ca-certificates \



  if ! command -v virtualenv > /dev/null ; then
    echo Failed to install a working \"virtualenv\" command, exiting
    exit 1
  fi
}

BootstrapRpmCommon() {
  # Tested with:
  #   - Fedora 20, 21, 22, 23 (x64)
  #   - Centos 7 (x64: on DigitalOcean droplet)
  #   - CentOS 7 Minimal install in a Hyper-V VM
  #   - CentOS 6 (EPEL must be installed manually)

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

  if [ "$ASSUME_YES" = 1 ]; then
    yes_flag="-y"
  fi

  if ! $SUDO $tool list *virtualenv >/dev/null 2>&1; then
    echo "To use Certbot, packages from the EPEL repository need to be installed."
    if ! $SUDO $tool list epel-release >/dev/null 2>&1; then
      echo "Please enable this repository and try running Certbot again."
      exit 1
    fi
    if [ "$ASSUME_YES" = 1 ]; then
        /bin/echo -n "Enabling the EPEL repository in 3 seconds..."
        sleep 1s
        /bin/echo -ne "\e[0K\rEnabling the EPEL repository in 2 seconds..."
        sleep 1s
        /bin/echo -e "\e[0K\rEnabling the EPEL repository in 1 seconds..."
        sleep 1s
    fi
    if ! $SUDO $tool install $yes_flag epel-release; then
      echo "Could not enable EPEL. Aborting bootstrap!"
      exit 1
    fi
  fi

  pkgs="
    gcc
    dialog
    augeas-libs
    openssl
    openssl-devel
    libffi-devel
    redhat-rpm-config
    ca-certificates
  "

  # Some distros and older versions of current distros use a "python27"
  # instead of "python" naming convention. Try both conventions.
  if $SUDO $tool list python >/dev/null 2>&1; then
    pkgs="$pkgs
      python
      python-devel
      python-virtualenv
      python-tools
      python-pip
    "
  else
    pkgs="$pkgs
      python27
      python27-devel
      python27-virtualenv
      python27-tools
      python27-pip
    "
  fi

  if $SUDO $tool list installed "httpd" >/dev/null 2>&1; then
    pkgs="$pkgs
      mod_ssl
    "
  fi

  if ! $SUDO $tool install $yes_flag $pkgs; then
      echo "Could not install OS dependencies. Aborting bootstrap!"
      exit 1
  fi
}

BootstrapSuseCommon() {
  # SLE12 don't have python-virtualenv

  if [ "$ASSUME_YES" = 1 ]; then
    zypper_flags="-nq"
    install_flags="-l"
  fi

  $SUDO zypper $zypper_flags in $install_flags \
    python \
    python-devel \
    python-virtualenv \
    gcc \
    dialog \
    augeas-lenses \
    libopenssl-devel \
    libffi-devel \
    ca-certificates
}

BootstrapArchCommon() {
  # Tested with:
  #   - ArchLinux (x86_64)
  #
  # "python-virtualenv" is Python3, but "python2-virtualenv" provides
  # only "virtualenv2" binary, not "virtualenv" necessary in
  # ./tools/_venv_common.sh

  deps="
    python2
    python-virtualenv
    gcc
    dialog
    augeas
    openssl
    libffi
    ca-certificates
    pkg-config
  "

  # pacman -T exits with 127 if there are missing dependencies
  missing=$($SUDO pacman -T $deps) || true

  if [ "$ASSUME_YES" = 1 ]; then
    noconfirm="--noconfirm"
  fi

  if [ "$missing" ]; then
    $SUDO pacman -S --needed $missing $noconfirm
  fi
}

BootstrapGentooCommon() {
  PACKAGES="
    dev-lang/python:2.7
    dev-python/virtualenv
    dev-util/dialog
    app-admin/augeas
    dev-libs/openssl
    dev-libs/libffi
    app-misc/ca-certificates
    virtual/pkgconfig"

  case "$PACKAGE_MANAGER" in
    (paludis)
      $SUDO cave resolve --preserve-world --keep-targets if-possible $PACKAGES -x
      ;;
    (pkgcore)
      $SUDO pmerge --noreplace --oneshot $PACKAGES
      ;;
    (portage|*)
      $SUDO emerge --noreplace --oneshot $PACKAGES
      ;;
  esac
}

BootstrapFreeBsd() {
  $SUDO pkg install -Ay \
    python \
    py27-virtualenv \
    augeas \
    libffi
}

BootstrapMac() {
  if hash brew 2>/dev/null; then
    echo "Using Homebrew to install dependencies..."
    pkgman=brew
    pkgcmd="brew install"
  elif hash port 2>/dev/null; then
    echo "Using MacPorts to install dependencies..."
    pkgman=port
    pkgcmd="$SUDO port install"
  else
    echo "No Homebrew/MacPorts; installing Homebrew..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    pkgman=brew
    pkgcmd="brew install"
  fi

  $pkgcmd augeas
  $pkgcmd dialog
  if [ "$(which python)" = "/System/Library/Frameworks/Python.framework/Versions/2.7/bin/python" \
      -o "$(which python)" = "/usr/bin/python" ]; then
    # We want to avoid using the system Python because it requires root to use pip.
    # python.org, MacPorts or HomeBrew Python installations should all be OK.
    echo "Installing python..."
    $pkgcmd python
  fi

  # Workaround for _dlopen not finding augeas on OS X
  if [ "$pkgman" = "port" ] && ! [ -e "/usr/local/lib/libaugeas.dylib" ] && [ -e "/opt/local/lib/libaugeas.dylib" ]; then
    echo "Applying augeas workaround"
    $SUDO mkdir -p /usr/local/lib/
    $SUDO ln -s /opt/local/lib/libaugeas.dylib /usr/local/lib/
  fi

  if ! hash pip 2>/dev/null; then
      echo "pip not installed"
      echo "Installing pip..."
      curl --silent --show-error --retry 5 https://bootstrap.pypa.io/get-pip.py | python
  fi

  if ! hash virtualenv 2>/dev/null; then
      echo "virtualenv not installed."
      echo "Installing with pip..."
      pip install virtualenv
  fi
}

BootstrapSmartOS() {
  pkgin update
  pkgin -y install 'gcc49' 'py27-augeas' 'py27-virtualenv'
}

BootstrapMageiaCommon() {
    if ! $SUDO urpmi --force  \
           python \
           libpython-devel \
           python-virtualenv
    then
      echo "Could not install Python dependencies. Aborting bootstrap!"
      exit 1
    fi

    if ! $SUDO urpmi --force \
           git \
           gcc \
           cdialog \
           python-augeas \
           libopenssl-devel \
           libffi-devel \
           rootcerts
    then
        echo "Could not install additional dependencies. Aborting bootstrap!"
        exit 1
    fi
}


# Install required OS packages:
Bootstrap() {
  if [ -f /etc/debian_version ]; then
    echo "Bootstrapping dependencies for Debian-based OSes..."
    BootstrapDebCommon
  elif [ -f /etc/mageia-release ] ; then
    # Mageia has both /etc/mageia-release and /etc/redhat-release
    ExperimentalBootstrap "Mageia" BootstrapMageiaCommon
  elif [ -f /etc/redhat-release ]; then
    echo "Bootstrapping dependencies for RedHat-based OSes..."
    BootstrapRpmCommon
  elif [ -f /etc/os-release ] && `grep -q openSUSE /etc/os-release` ; then
    echo "Bootstrapping dependencies for openSUSE-based OSes..."
    BootstrapSuseCommon
  elif [ -f /etc/arch-release ]; then
    if [ "$DEBUG" = 1 ]; then
      echo "Bootstrapping dependencies for Archlinux..."
      BootstrapArchCommon
    else
      echo "Please use pacman to install letsencrypt packages:"
      echo "# pacman -S certbot certbot-apache"
      echo
      echo "If you would like to use the virtualenv way, please run the script again with the"
      echo "--debug flag."
      exit 1
    fi
  elif [ -f /etc/manjaro-release ]; then
    ExperimentalBootstrap "Manjaro Linux" BootstrapArchCommon
  elif [ -f /etc/gentoo-release ]; then
    ExperimentalBootstrap "Gentoo" BootstrapGentooCommon
  elif uname | grep -iq FreeBSD ; then
    ExperimentalBootstrap "FreeBSD" BootstrapFreeBsd
  elif uname | grep -iq Darwin ; then
    ExperimentalBootstrap "Mac OS X" BootstrapMac
  elif [ -f /etc/issue ] && grep -iq "Amazon Linux" /etc/issue ; then
    ExperimentalBootstrap "Amazon Linux" BootstrapRpmCommon
  elif [ -f /etc/product ] && grep -q "Joyent Instance" /etc/product ; then
    ExperimentalBootstrap "Joyent SmartOS Zone" BootstrapSmartOS
  else
    echo "Sorry, I don't know how to bootstrap Certbot on your operating system!"
    echo
    echo "You will need to bootstrap, configure virtualenv, and run pip install manually."
    echo "Please see https://letsencrypt.readthedocs.org/en/latest/contributing.html#prerequisites"
    echo "for more info."
    exit 1
  fi
}

TempDir() {
  mktemp -d 2>/dev/null || mktemp -d -t 'le'  # Linux || OS X
}



if [ "$1" = "--le-auto-phase2" ]; then
  # Phase 2: Create venv, install LE, and run.

  shift 1  # the --le-auto-phase2 arg
  if [ -f "$VENV_BIN/letsencrypt" ]; then
    # --version output ran through grep due to python-cryptography DeprecationWarnings
    # grep for both certbot and letsencrypt until certbot and shim packages have been released
    INSTALLED_VERSION=$("$VENV_BIN/letsencrypt" --version 2>&1 | grep "^certbot\|^letsencrypt" | cut -d " " -f 2)
  else
    INSTALLED_VERSION="none"
  fi
  if [ "$LE_AUTO_VERSION" != "$INSTALLED_VERSION" ]; then
    echo "Creating virtual environment..."
    DeterminePythonVersion
    rm -rf "$VENV_PATH"
    if [ "$VERBOSE" = 1 ]; then
      virtualenv --no-site-packages --python "$LE_PYTHON" "$VENV_PATH"
    else
      virtualenv --no-site-packages --python "$LE_PYTHON" "$VENV_PATH" > /dev/null
    fi

    echo "Installing Python packages..."
    TEMP_DIR=$(TempDir)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    # There is no $ interpolation due to quotes on starting heredoc delimiter.
    # -------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/letsencrypt-auto-requirements.txt"
# This is the flattened list of packages certbot-auto installs. To generate
# this, do
# `pip install --no-cache-dir -e acme -e . -e certbot-apache -e certbot-nginx`,
# and then use `hashin` or a more secure method to gather the hashes.

argparse==1.4.0 \
    --hash=sha256:c31647edb69fd3d465a847ea3157d37bed1f95f19760b11a47aa91c04b666314 \
    --hash=sha256:62b089a55be1d8949cd2bc7e0df0bddb9e028faefc8c32038cc84862aefdd6e4

# This comes before cffi because cffi will otherwise install an unchecked
# version via setup_requires.
pycparser==2.14 \
    --hash=sha256:7959b4a74abdc27b312fed1c21e6caf9309ce0b29ea86b591fd2e99ecdf27f73

cffi==1.4.2 \
    --hash=sha256:53c1c9ddb30431513eb7f3cdef0a3e06b0f1252188aaa7744af0f5a4cd45dbaf \
    --hash=sha256:a568f49dfca12a8d9f370187257efc58a38109e1eee714d928561d7a018a64f8 \
    --hash=sha256:809c6ca8cfbcaeebfbd432b4576001b40d38ff2463773cb57577d75e1a020bc3 \
    --hash=sha256:86cdca2cd9cba41422230390df17dfeaa9f344a911e3975c8be9da57b35548e9 \
    --hash=sha256:24b13db84aec385ca23c7b8ded83ef8bb4177bc181d14758f9f975be5d020d86 \
    --hash=sha256:969aeffd7c0e097f6be1efd682c156ae226591a0793a94b6c2d5e4293f4c8d4e \
    --hash=sha256:000f358d4b0fa249feaab9c1ce7d5b2fe7e02e7bdf6806c26418505fc685e268 \
    --hash=sha256:a9d86f460bbd8358a2d513ad779e3f3fc878e3b93a00b5002faebf616ffe6b9c \
    --hash=sha256:3127b3ab33eb23ccac071f9a0802748e5cf7c5cbcd02482bb063e35b41dbb0b0 \
    --hash=sha256:e2b2d42236469a40224d39e7b6c60575f388b2f423f354c7ee90a5b7f58c8065 \
    --hash=sha256:8c2dccafee89b1b424b0bec6ad2dd9622c949d2024e929f5da1ed801eac75f1d \
    --hash=sha256:a4de7a4d11aed488bab4fb14f4988587a829bece5a20433f780d6e33b08083cb \
    --hash=sha256:5ca8fe30425265a49274e4b0213a1bc98f4b13449ae5e96f984771e5d83e58c1 \
    --hash=sha256:a4fd38802f59e714eba81a024f62db710b27dbe27a7ea12e911537327aa84d30 \
    --hash=sha256:86cd6912bbc83e9405d4a73cd7f4b4ee8353652d2dbc7c820106ed5b4d1bab3a \
    --hash=sha256:8f1d177d364ea35900415ae24ca3e471be3d5334ed0419294068c49f45913998
ConfigArgParse==0.10.0 \
    --hash=sha256:3b50a83dd58149dfcee98cb6565265d10b53e9c0a2bca7eeef7fb5f5524890a7
configobj==5.0.6 \
    --hash=sha256:a2f5650770e1c87fb335af19a9b7eb73fc05ccf22144eb68db7d00cd2bcb0902
cryptography==1.3.4 \
    --hash=sha256:bede00edd11a2a62c8c98c271cc103fa3a3d72acf64f6e5e4eaf251128897b17 \
    --hash=sha256:53b39e687b744bb548a98f40736cc529d9f60959b4e6cc551322cf9505d35eb3 \
    --hash=sha256:474b73ad1139b4e423e46bbd818efd0d5c0df1c65d9f7c957d64c9215d77afde \
    --hash=sha256:aaddf9592d5b99e32dd518bb4a25b147c124f9d6b4ad64b94f01b15d1666b8c8 \
    --hash=sha256:6dcad2f407db8c3cd6ecd78361439c449a4f94786b46c54507e7e68f51e1709d \
    --hash=sha256:475c153fc622e656f1f10a9c9941d0ac7ab18df7c38d35d563a437c1c0e34f24 \
    --hash=sha256:86dd61df581cba04e89e45081efbc531faff1c9d99c77b1ce97f87216c356353 \
    --hash=sha256:75cc697e4ef5fdd0102ca749114c6370dbd11db0c9132a18834858c2566247e3 \
    --hash=sha256:ea03ad5b9df6d79fc9fc1ab23729e01e1c920d2974c5e3c634ccf45a5c378452 \
    --hash=sha256:c8872b8fe4f3416d6338ab99612f49ab314f7856cb43bffab2a32d28a6267be8 \
    --hash=sha256:468fc6e16eaec6ceaa6bc341273e6e9912d01b42b740f8cf896ace7fcd6a321d \
    --hash=sha256:d6fea3c6502735011c5d61a62aef1c1d770fc6a2def45d9e6c0d94c9651e3317 \
    --hash=sha256:3cf95f179f4bead3d5649b91860ef4cf60ad4244209190fc405908272576d961 \
    --hash=sha256:141f77e60a5b9158309b2b60288c7f81d37faa15c22a69b94c190ceefaaa6236 \
    --hash=sha256:87b7a1fe703c6424451f3372d1879dae91c7fe5e13375441a72833db76fee30e \
    --hash=sha256:f5ee3cb0cf1a6550bf483ccffa6608db267a377b45f7e3a8201a86d1d8feb19f \
    --hash=sha256:4e097286651ea318300af3251375d48b71b8228481c56cd617ddd4459a1ff261 \
    --hash=sha256:1e3d3ae3f22f22d50d340f47f25227511326f3f1396c6d2446a5b45b516c4313 \
    --hash=sha256:6a057941cb64d79834ea3cf99093fcc4787c2a5d44f686c4f297361ddc419bcd \
    --hash=sha256:68b3d5390b92559ddd3353c73ab2dfcff758f9c4ec4f5d5226ccede0e5d779f4 \
    --hash=sha256:545dc003b4b6081f9c3e452da15d819b04b696f49484aff64c0a2aedf766bef8 \
    --hash=sha256:423ff890c01be7c70dbfeaa967eeef5146f1a43a5f810ffdc07b178e48a105a9
enum34==1.1.2 \
    --hash=sha256:2475d7fcddf5951e92ff546972758802de5260bf409319a9f1934e6bbc8b1dc7 \
    --hash=sha256:35907defb0f992b75ab7788f65fedc1cf20ffa22688e0e6f6f12afc06b3ea501
funcsigs==0.4 \
    --hash=sha256:ff5ad9e2f8d9e5d1e8bbfbcf47722ab527cf0d51caeeed9da6d0f40799383fde \
    --hash=sha256:d83ce6df0b0ea6618700fe1db353526391a8a3ada1b7aba52fed7a61da772033
idna==2.0 \
    --hash=sha256:9b2fc50bd3c4ba306b9651b69411ef22026d4d8335b93afc2214cef1246ce707 \
    --hash=sha256:16199aad938b290f5be1057c0e1efc6546229391c23cea61ca940c115f7d3d3b
ipaddress==1.0.16 \
    --hash=sha256:935712800ce4760701d89ad677666cd52691fd2f6f0b340c8b4239a3c17988a5 \
    --hash=sha256:5a3182b322a706525c46282ca6f064d27a02cffbd449f9f47416f1dc96aa71b0
linecache2==1.0.0 \
    --hash=sha256:e78be9c0a0dfcbac712fe04fbf92b96cddae80b1b842f24248214c8496f006ef \
    --hash=sha256:4b26ff4e7110db76eeb6f5a7b64a82623839d595c2038eeda662f2a2db78e97c
ndg-httpsclient==0.4.0 \
    --hash=sha256:e8c155fdebd9c4bcb0810b4ed01ae1987554b1ee034dd7532d7b8fdae38a6274
ordereddict==1.1 \
    --hash=sha256:1c35b4ac206cef2d24816c89f89cf289dd3d38cf7c449bb3fab7bf6d43f01b1f
parsedatetime==2.1 \
    --hash=sha256:ce9d422165cf6e963905cd5f74f274ebf7cc98c941916169178ef93f0e557838 \
    --hash=sha256:17c578775520c99131634e09cfca5a05ea9e1bd2a05cd06967ebece10df7af2d
pbr==1.8.1 \
    --hash=sha256:46c8db75ae75a056bd1cc07fa21734fe2e603d11a07833ecc1eeb74c35c72e0c \
    --hash=sha256:e2127626a91e6c885db89668976db31020f0af2da728924b56480fc7ccf09649
pyasn1==0.1.9 \
    --hash=sha256:61f9d99e3cef65feb1bfe3a2eef7a93eb93819d345bf54bcd42f4e63d5204dae \
    --hash=sha256:1802a6dd32045e472a419db1441aecab469d33e0d2749e192abdec52101724af \
    --hash=sha256:35025cd9422c96504912f04e2f15fe79390a8597b430c2ca5d0534cf9309ffa0 \
    --hash=sha256:2f96ed5a0c329ca16230b326ca12b7461ec8f65e0be3e4f997516f36bf82a345 \
    --hash=sha256:28fee44217991cfad9e6a0b9f7e3f26041e21ebc96629e94e585ccd05d49fa65 \
    --hash=sha256:326e7a854a17fab07691204747695f8f692d674588a355c441fb14f660bf4e68 \
    --hash=sha256:cda5a90485709ca6795c86056c3e5fe7266028b05e53f1d527fdf93a6365a6b8 \
    --hash=sha256:0cb2a14742b543fdd68f931a14ce3829186ed2b1b2267a06787388c96b2dd9be \
    --hash=sha256:5191ff6b9126d2c039dd87f8ff025bed274baf07fa78afa46f556b1ad7265d6e \
    --hash=sha256:8323e03637b2d072cc7041300bac6ec448c3c28950ab40376036788e9a1af629 \
    --hash=sha256:853cacd96d1f701ddd67aa03ecc05f51890135b7262e922710112f12a2ed2a7f
pyopenssl==16.0.0 \
    --hash=sha256:5add70cf00273bf957ca31fdb0df9b0ae4639e081897d5f86a0ae1f104901230 \
    --hash=sha256:363d10ee43d062285facf4e465f4f5163f9f702f9134f0a5896f134cbb92d17d
pyparsing==2.1.8 \
    --hash=sha256:2f0f5ceb14eccd5aef809d6382e87df22ca1da583c79f6db01675ce7d7f49c18 \
    --hash=sha256:03a4869b9f3493807ee1f1cb405e6d576a1a2ca4d81a982677c0c1ad6177c56b \
    --hash=sha256:ab09aee814c0241ff0c503cff30018219fe1fc14501d89f406f4664a0ec9fbcd \
    --hash=sha256:6e9a7f052f8e26bcf749e4033e3115b6dc7e3c85aafcb794b9a88c9d9ef13c97 \
    --hash=sha256:9f463a6bcc4eeb6c08f1ed84439b17818e2085937c0dee0d7674ac127c67c12b \
    --hash=sha256:3626b4d81cfb300dad57f52f2f791caaf7b06c09b368c0aa7b868e53a5775424 \
    --hash=sha256:367b90cc877b46af56d4580cd0ae278062903f02b8204ab631f5a2c0f50adfd0 \
    --hash=sha256:9f1ea360086cd68681e7f4ca8f1f38df47bf81942a0d76a9673c2d23eff35b13
pyRFC3339==1.0 \
    --hash=sha256:eea31835c56e2096af4363a5745a784878a61d043e247d3a6d6a0a32a9741f56 \
    --hash=sha256:8dfbc6c458b8daba1c0f3620a8c78008b323a268b27b7359e92a4ae41325f535
python-augeas==0.5.0 \
    --hash=sha256:67d59d66cdba8d624e0389b87b2a83a176f21f16a87553b50f5703b23f29bac2
python2-pythondialog==3.3.0 \
    --hash=sha256:04e93f24995c43dd90f338d5d865ca72ce3fb5a5358d4daa4965571db35fc3ec \
    --hash=sha256:3e6f593fead98f8a526bc3e306933533236e33729f552f52896ea504f55313fa
pytz==2015.7 \
    --hash=sha256:3abe6a6d3fc2fbbe4c60144211f45da2edbe3182a6f6511af6bbba0598b1f992 \
    --hash=sha256:939ef9c1e1224d980405689a97ffcf7828c56d1517b31d73464356c1f2b7769e \
    --hash=sha256:ead4aefa7007249e05e51b01095719d5a8dd95760089f5730aac5698b1932918 \
    --hash=sha256:3cca0df08bd0ed98432390494ce3ded003f5e661aa460be7a734bffe35983605 \
    --hash=sha256:3ede470d3d17ba3c07638dfa0d10452bc1b6e5ad326127a65ba77e6aaeb11bec \
    --hash=sha256:68c47964f7186eec306b13629627722b9079cd4447ed9e5ecaecd4eac84ca734 \
    --hash=sha256:dd5d3991950aae40a6c81de1578942e73d629808cefc51d12cd157980e6cfc18 \
    --hash=sha256:a77c52062c07eb7c7b30545dbc73e32995b7e117eea750317b5cb5c7a4618f14 \
    --hash=sha256:81af9aec4bc960a9a0127c488f18772dae4634689233f06f65443e7b11ebeb51 \
    --hash=sha256:e079b1dadc5c06246cc1bb6fe1b23a50b1d1173f2edd5104efd40bb73a28f406 \
    --hash=sha256:fbd26746772c24cb93c8b97cbdad5cb9e46c86bbdb1b9d8a743ee00e2fb1fc5d \
    --hash=sha256:99266ef30a37e43932deec2b7ca73e83c8dbc3b9ff703ec73eca6b1dae6befea \
    --hash=sha256:8b6ce1c993909783bc96e0b4f34ea223bff7a4df2c90bdb9c4e0f1ac928689e3
requests==2.9.1 \
    --hash=sha256:113fbba5531a9e34945b7d36b33a084e8ba5d0664b703c81a7c572d91919a5b8 \
    --hash=sha256:c577815dd00f1394203fc44eb979724b098f88264a9ef898ee45b8e5e9cf587f
six==1.10.0 \
    --hash=sha256:0ff78c403d9bccf5a425a6d31a12aa6b47f1c21ca4dc2573a7e2f32a97335eb1 \
    --hash=sha256:105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a
traceback2==1.4.0 \
    --hash=sha256:8253cebec4b19094d67cc5ed5af99bf1dba1285292226e98a31929f87a5d6b23 \
    --hash=sha256:05acc67a09980c2ecfedd3423f7ae0104839eccb55fc645773e1caa0951c3030
unittest2==1.1.0 \
    --hash=sha256:13f77d0875db6d9b435e1d4f41e74ad4cc2eb6e1d5c824996092b3430f088bb8 \
    --hash=sha256:22882a0e418c284e1f718a822b3b022944d53d2d908e1690b319a9d3eb2c0579
zope.component==4.2.2 \
    --hash=sha256:282c112b55dd8e3c869a3571f86767c150ab1284a9ace2bdec226c592acaf81a
zope.event==4.1.0 \
    --hash=sha256:dc7a59a2fd91730d3793131a5d261b29e93ec4e2a97f1bc487ce8defee2fe786
zope.interface==4.1.3 \
    --hash=sha256:f07b631f7a601cd8cbd3332d54f43142c7088a83299f859356f08d1d4d4259b3 \
    --hash=sha256:de5cca083b9439d8002fb76bbe6b4998c5a5a721fab25b84298967f002df4c94 \
    --hash=sha256:6788416f7ea7f5b8a97be94825377aa25e8bdc73463e07baaf9858b29e737077 \
    --hash=sha256:6f3230f7254518201e5a3708cbb2de98c848304f06e3ded8bfb39e5825cba2e1 \
    --hash=sha256:5fa575a5240f04200c3088427d0d4b7b737f6e9018818a51d8d0f927a6a2517a \
    --hash=sha256:522194ad6a545735edd75c8a83f48d65d1af064e432a7d320d64f56bafc12e99 \
    --hash=sha256:e8c7b2d40943f71c99148c97f66caa7f5134147f57423f8db5b4825099ce9a09 \
    --hash=sha256:279024f0208601c3caa907c53876e37ad88625f7eaf1cb3842dbe360b2287017 \
    --hash=sha256:2e221a9eec7ccc58889a278ea13dcfed5ef939d80b07819a9a8b3cb1c681484f \
    --hash=sha256:69118965410ec86d44dc6b9017ee3ddbd582e0c0abeef62b3a19dbf6c8ad132b \
    --hash=sha256:d04df8686ec864d0cade8cf199f7f83aecd416109a20834d568f8310ded12dea \
    --hash=sha256:e75a947e15ee97e7e71e02ea302feb2fc62d3a2bb4668bf9dfbed43a506ac7e7 \
    --hash=sha256:4e45d22fb883222a5ab9f282a116fec5ee2e8d1a568ccff6a2d75bbd0eb6bcfc \
    --hash=sha256:bce9339bb3c7a55e0803b63d21c5839e8e479bc85c4adf42ae415b72f94facb2 \
    --hash=sha256:928138365245a0e8869a5999fbcc2a45475a0a6ed52a494d60dbdc540335fedd \
    --hash=sha256:0d841ba1bb840eea0e6489dc5ecafa6125554971f53b5acb87764441e61bceba \
    --hash=sha256:b09c8c1d47b3531c400e0195697f1414a63221de6ef478598a4f1460f7d9a392
mock==1.0.1 \
    --hash=sha256:b839dd2d9c117c701430c149956918a423a9863b48b09c90e30a6013e7d2f44f \
    --hash=sha256:8f83080daa249d036cbccfb8ae5cc6ff007b88d6d937521371afabe7b19badbc
letsencrypt==0.7.0 \
    --hash=sha256:105a5fb107e45bcd0722eb89696986dcf5f08a86a321d6aef25a0c7c63375ade \
    --hash=sha256:c36e532c486a7e92155ee09da54b436a3c420813ec1c590b98f635d924720de9

# THE LINES BELOW ARE EDITED BY THE RELEASE SCRIPT; ADD ALL DEPENDENCIES ABOVE.

acme==0.9.3 \
    --hash=sha256:d18ce17a75ad24d27981dfaef0524aa905eab757b267e027162b56a8967ab8fb \
    --hash=sha256:a6eff1f955eb2e4316abd9aa2fedb6d9345e6b5b8a2d64ea0ad35e05d6124099
certbot==0.9.3 \
    --hash=sha256:a87ef4c53c018df4e52ee2f2e906ad16bbb37789f29e6f284c495a2eb4d9b243 \
    --hash=sha256:68149cb8392b29f5d5246e7226d25f913f2b10482bf3bc7368e8c8821d25f3b0
certbot-apache==0.9.3 \
    --hash=sha256:f379b1053e10709692654d7a6fcea9eaed19b66c49a753b61e31bd06a04b0aac \
    --hash=sha256:a5d98cf972072de08f984db4e6a7f20269f3f023c43f6d4e781fe43be7c10086
certbot-nginx==0.9.3 \
    --hash=sha256:3c26f18f0b57550f069263bd9b2984ef33eab6693e7796611c1b2cc16574069c \
    --hash=sha256:7337a2e90e0b28a1ab09e31d9fb81c6d78e6453500c824c0f18bab5d31b63058

UNLIKELY_EOF
    # -------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/pipstrap.py"
#!/usr/bin/env python
"""A small script that can act as a trust root for installing pip 8

Embed this in your project, and your VCS checkout is all you have to trust. In
a post-peep era, this lets you claw your way to a hash-checking version of pip,
with which you can install the rest of your dependencies safely. All it assumes
is Python 2.6 or better and *some* version of pip already installed. If
anything goes wrong, it will exit with a non-zero status code.

"""
# This is here so embedded copies are MIT-compliant:
# Copyright (c) 2016 Erik Rose
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
from __future__ import print_function
from hashlib import sha256
from os.path import join
from pipes import quote
from shutil import rmtree
try:
    from subprocess import check_output
except ImportError:
    from subprocess import CalledProcessError, PIPE, Popen

    def check_output(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be '
                             'overridden.')
        process = Popen(stdout=PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise CalledProcessError(retcode, cmd)
        return output
from sys import exit, version_info
from tempfile import mkdtemp
try:
    from urllib2 import build_opener, HTTPHandler, HTTPSHandler
except ImportError:
    from urllib.request import build_opener, HTTPHandler, HTTPSHandler
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse  # 3.4


__version__ = 1, 1, 1


# wheel has a conditional dependency on argparse:
maybe_argparse = (
    [('https://pypi.python.org/packages/source/a/argparse/'
      'argparse-1.4.0.tar.gz',
      '62b089a55be1d8949cd2bc7e0df0bddb9e028faefc8c32038cc84862aefdd6e4')]
    if version_info < (2, 7, 0) else [])


PACKAGES = maybe_argparse + [
    # Pip has no dependencies, as it vendors everything:
    ('https://pypi.python.org/packages/source/p/pip/pip-8.0.3.tar.gz',
     '30f98b66f3fe1069c529a491597d34a1c224a68640c82caf2ade5f88aa1405e8'),
    # This version of setuptools has only optional dependencies:
    ('https://pypi.python.org/packages/source/s/setuptools/'
     'setuptools-20.2.2.tar.gz',
     '24fcfc15364a9fe09a220f37d2dcedc849795e3de3e4b393ee988e66a9cbd85a'),
    ('https://pypi.python.org/packages/source/w/wheel/wheel-0.29.0.tar.gz',
     '1ebb8ad7e26b448e9caa4773d2357849bf80ff9e313964bcaf79cbf0201a1648')
]


class HashError(Exception):
    def __str__(self):
        url, path, actual, expected = self.args
        return ('{url} did not match the expected hash {expected}. Instead, '
                'it was {actual}. The file (left at {path}) may have been '
                'tampered with.'.format(**locals()))


def hashed_download(url, temp, digest):
    """Download ``url`` to ``temp``, make sure it has the SHA-256 ``digest``,
    and return its path."""
    # Based on pip 1.4.1's URLOpener but with cert verification removed. Python
    # >=2.7.9 verifies HTTPS certs itself, and, in any case, the cert
    # authenticity has only privacy (not arbitrary code execution)
    # implications, since we're checking hashes.
    def opener():
        opener = build_opener(HTTPSHandler())
        # Strip out HTTPHandler to prevent MITM spoof:
        for handler in opener.handlers:
            if isinstance(handler, HTTPHandler):
                opener.handlers.remove(handler)
        return opener

    def read_chunks(response, chunk_size):
        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            yield chunk

    response = opener().open(url)
    path = join(temp, urlparse(url).path.split('/')[-1])
    actual_hash = sha256()
    with open(path, 'wb') as file:
        for chunk in read_chunks(response, 4096):
            file.write(chunk)
            actual_hash.update(chunk)

    actual_digest = actual_hash.hexdigest()
    if actual_digest != digest:
        raise HashError(url, path, actual_digest, digest)
    return path


def main():
    temp = mkdtemp(prefix='pipstrap-')
    try:
        downloads = [hashed_download(url, temp, digest)
                     for url, digest in PACKAGES]
        check_output('pip install --no-index --no-deps -U ' +
                     ' '.join(quote(d) for d in downloads),
                     shell=True)
    except HashError as exc:
        print(exc)
    except Exception:
        rmtree(temp)
        raise
    else:
        rmtree(temp)
        return 0
    return 1


if __name__ == '__main__':
    exit(main())

UNLIKELY_EOF
    # -------------------------------------------------------------------------
    # Set PATH so pipstrap upgrades the right (v)env:
    PATH="$VENV_BIN:$PATH" "$VENV_BIN/python" "$TEMP_DIR/pipstrap.py"
    set +e
    if [ "$VERBOSE" = 1 ]; then
      "$VENV_BIN/pip" install --no-cache-dir --require-hashes -r "$TEMP_DIR/letsencrypt-auto-requirements.txt"
    else
      PIP_OUT=`"$VENV_BIN/pip" install --no-cache-dir --require-hashes -r "$TEMP_DIR/letsencrypt-auto-requirements.txt" 2>&1`
    fi
    PIP_STATUS=$?
    set -e
    if [ "$PIP_STATUS" != 0 ]; then
      # Report error. (Otherwise, be quiet.)
      echo "Had a problem while installing Python packages."
      if [ "$VERBOSE" != 1 ]; then
        echo "$PIP_OUT"
      fi
      rm -rf "$VENV_PATH"
      exit 1
    fi
    echo "Installation succeeded."
  fi
  if [ -n "$SUDO" ]; then
    # SUDO is su wrapper or sudo
    if [  "$QUIET" != 1 ]; then
      echo "Requesting root privileges to run certbot..."
      echo "  $VENV_BIN/letsencrypt" "$@"
    fi
  fi
  if [ -z "$SUDO_ENV" ] ; then
    # SUDO is su wrapper / noop
    $SUDO "$VENV_BIN/letsencrypt" "$@"
  else
    # sudo
    $SUDO "$SUDO_ENV" "$VENV_BIN/letsencrypt" "$@"
  fi

else
  # Phase 1: Upgrade certbot-auto if neceesary, then self-invoke.
  #
  # Each phase checks the version of only the thing it is responsible for
  # upgrading. Phase 1 checks the version of the latest release of
  # certbot-auto (which is always the same as that of the certbot
  # package). Phase 2 checks the version of the locally installed certbot.

  if [ ! -f "$VENV_BIN/letsencrypt" ]; then
    if [ "$HELP" = 1 ]; then
      echo "$USAGE"
      exit 0
    fi
    # If it looks like we've never bootstrapped before, bootstrap:
    Bootstrap
  fi
  if [ "$OS_PACKAGES_ONLY" = 1 ]; then
    echo "OS packages installed."
    exit 0
  fi

  if [ "$NO_SELF_UPGRADE" != 1 ]; then
    TEMP_DIR=$(TempDir)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    # ---------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/fetch.py"
"""Do downloading and JSON parsing without additional dependencies. ::

    # Print latest released version of LE to stdout:
    python fetch.py --latest-version

    # Download letsencrypt-auto script from git tag v1.2.3 into the folder I'm
    # in, and make sure its signature verifies:
    python fetch.py --le-auto-script v1.2.3

On failure, return non-zero.

"""
from distutils.version import LooseVersion
from json import loads
from os import devnull, environ
from os.path import dirname, join
import re
from subprocess import check_call, CalledProcessError
from sys import argv, exit
from urllib2 import build_opener, HTTPHandler, HTTPSHandler, HTTPError

PUBLIC_KEY = environ.get('LE_AUTO_PUBLIC_KEY', """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6MR8W/galdxnpGqBsYbq
OzQb2eyW15YFjDDEMI0ZOzt8f504obNs920lDnpPD2/KqgsfjOgw2K7xWDJIj/18
xUvWPk3LDkrnokNiRkA3KOx3W6fHycKL+zID7zy+xZYBuh2fLyQtWV1VGQ45iNRp
9+Zo7rH86cdfgkdnWTlNSHyTLW9NbXvyv/E12bppPcEvgCTAQXgnDVJ0/sqmeiij
n9tTFh03aM+R2V/21h8aTraAS24qiPCz6gkmYGC8yr6mglcnNoYbsLNYZ69zF1XH
cXPduCPdPdfLlzVlKK1/U7hkA28eG3BIAMh6uJYBRJTpiGgaGdPd7YekUB8S6cy+
CQIDAQAB
-----END PUBLIC KEY-----
""")

class ExpectedError(Exception):
    """A novice-readable exception that also carries the original exception for
    debugging"""


class HttpsGetter(object):
    def __init__(self):
        """Build an HTTPS opener."""
        # Based on pip 1.4.1's URLOpener
        # This verifies certs on only Python >=2.7.9.
        self._opener = build_opener(HTTPSHandler())
        # Strip out HTTPHandler to prevent MITM spoof:
        for handler in self._opener.handlers:
            if isinstance(handler, HTTPHandler):
                self._opener.handlers.remove(handler)

    def get(self, url):
        """Return the document contents pointed to by an HTTPS URL.

        If something goes wrong (404, timeout, etc.), raise ExpectedError.

        """
        try:
            return self._opener.open(url).read()
        except (HTTPError, IOError) as exc:
            raise ExpectedError("Couldn't download %s." % url, exc)


def write(contents, dir, filename):
    """Write something to a file in a certain directory."""
    with open(join(dir, filename), 'w') as file:
        file.write(contents)


def latest_stable_version(get):
    """Return the latest stable release of letsencrypt."""
    metadata = loads(get(
        environ.get('LE_AUTO_JSON_URL',
                    'https://pypi.python.org/pypi/certbot/json')))
    # metadata['info']['version'] actually returns the latest of any kind of
    # release release, contrary to https://wiki.python.org/moin/PyPIJSON.
    # The regex is a sufficient regex for picking out prereleases for most
    # packages, LE included.
    return str(max(LooseVersion(r) for r
                   in metadata['releases'].iterkeys()
                   if re.match('^[0-9.]+$', r)))


def verified_new_le_auto(get, tag, temp_dir):
    """Return the path to a verified, up-to-date letsencrypt-auto script.

    If the download's signature does not verify or something else goes wrong
    with the verification process, raise ExpectedError.

    """
    le_auto_dir = environ.get(
        'LE_AUTO_DIR_TEMPLATE',
        'https://raw.githubusercontent.com/certbot/certbot/%s/'
        'letsencrypt-auto-source/') % tag
    write(get(le_auto_dir + 'letsencrypt-auto'), temp_dir, 'letsencrypt-auto')
    write(get(le_auto_dir + 'letsencrypt-auto.sig'), temp_dir, 'letsencrypt-auto.sig')
    write(PUBLIC_KEY, temp_dir, 'public_key.pem')
    try:
        with open(devnull, 'w') as dev_null:
            check_call(['openssl', 'dgst', '-sha256', '-verify',
                        join(temp_dir, 'public_key.pem'),
                        '-signature',
                        join(temp_dir, 'letsencrypt-auto.sig'),
                        join(temp_dir, 'letsencrypt-auto')],
                       stdout=dev_null,
                       stderr=dev_null)
    except CalledProcessError as exc:
        raise ExpectedError("Couldn't verify signature of downloaded "
                            "certbot-auto.", exc)


def main():
    get = HttpsGetter().get
    flag = argv[1]
    try:
        if flag == '--latest-version':
            print latest_stable_version(get)
        elif flag == '--le-auto-script':
            tag = argv[2]
            verified_new_le_auto(get, tag, dirname(argv[0]))
    except ExpectedError as exc:
        print exc.args[0], exc.args[1]
        return 1
    else:
        return 0


if __name__ == '__main__':
    exit(main())

UNLIKELY_EOF
    # ---------------------------------------------------------------------------
    DeterminePythonVersion
    if ! REMOTE_VERSION=`"$LE_PYTHON" "$TEMP_DIR/fetch.py" --latest-version` ; then
      echo "WARNING: unable to check for updates."
    elif [ "$LE_AUTO_VERSION" != "$REMOTE_VERSION" ]; then
      echo "Upgrading certbot-auto $LE_AUTO_VERSION to $REMOTE_VERSION..."

      # Now we drop into Python so we don't have to install even more
      # dependencies (curl, etc.), for better flow control, and for the option of
      # future Windows compatibility.
      "$LE_PYTHON" "$TEMP_DIR/fetch.py" --le-auto-script "v$REMOTE_VERSION"

      # Install new copy of certbot-auto.
      # TODO: Deal with quotes in pathnames.
      echo "Replacing certbot-auto..."
      # Clone permissions with cp. chmod and chown don't have a --reference
      # option on OS X or BSD, and stat -c on Linux is stat -f on OS X and BSD:
      $SUDO cp -p "$0" "$TEMP_DIR/letsencrypt-auto.permission-clone"
      $SUDO cp "$TEMP_DIR/letsencrypt-auto" "$TEMP_DIR/letsencrypt-auto.permission-clone"
      # Using mv rather than cp leaves the old file descriptor pointing to the
      # original copy so the shell can continue to read it unmolested. mv across
      # filesystems is non-atomic, doing `rm dest, cp src dest, rm src`, but the
      # cp is unlikely to fail (esp. under sudo) if the rm doesn't.
      $SUDO mv -f "$TEMP_DIR/letsencrypt-auto.permission-clone" "$0"
    fi  # A newer version is available.
  fi  # Self-upgrading is allowed.

  "$0" --le-auto-phase2 "$@"
fi
