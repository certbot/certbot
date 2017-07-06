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

# HOME might not be defined when being run through something like systemd
if [ -z "$HOME" ]; then
  HOME=~root
fi
if [ -z "$XDG_DATA_HOME" ]; then
  XDG_DATA_HOME=~/.local/share
fi
VENV_NAME="letsencrypt"
if [ -z "$VENV_PATH" ]; then
  VENV_PATH="$XDG_DATA_HOME/$VENV_NAME"
fi
VENV_BIN="$VENV_PATH/bin"
LE_AUTO_VERSION="0.15.0"
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
  --no-bootstrap                            do not install OS dependencies
  --no-self-upgrade                         do not download updates
  --os-packages-only                        install OS dependencies and exit
  -v, --verbose                             provide more output
  -q, --quiet                               provide only update/error output;
                                            implies --non-interactive

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
    --no-bootstrap)
      NO_BOOTSTRAP=1;;
    --help)
      HELP=1;;
    --noninteractive|--non-interactive|renew)
      ASSUME_YES=1;;
    --quiet)
      QUIET=1;;
    --verbose)
      VERBOSE=1;;
    -[!-]*)
      OPTIND=1
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

# Set ASSUME_YES to 1 if QUIET (i.e. --quiet implies --non-interactive)
if [ "$QUIET" = 1 ]; then
  ASSUME_YES=1
fi

say() {
    if [  "$QUIET" != 1 ]; then
        echo "$@"
    fi
}

error() {
    echo "$@"
}

# Support for busybox and others where there is no "command",
# but "which" instead
if command -v command > /dev/null 2>&1 ; then
  export EXISTS="command -v"
elif which which > /dev/null 2>&1 ; then
  export EXISTS="which"
else
  error "Cannot find command nor which... please install one!"
  exit 1
fi

# certbot-auto needs root access to bootstrap OS dependencies, and
# certbot itself needs root access for almost all modes of operation
# The "normal" case is that sudo is used for the steps that need root, but
# this script *can* be run as root (not recommended), or fall back to using
# `su`. Auto-detection can be overridden by explicitly setting the
# environment variable LE_AUTO_SUDO to 'sudo', 'sudo_su' or '' as used below.

# Because the parameters in `su -c` has to be a string,
# we need to properly escape it.
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

SUDO_ENV=""
export CERTBOT_AUTO="$0"
if [ -n "${LE_AUTO_SUDO+x}" ]; then
  case "$LE_AUTO_SUDO" in
    su_sudo|su)
      SUDO=su_sudo
      ;;
    sudo)
      SUDO=sudo
      SUDO_ENV="CERTBOT_AUTO=$0"
      ;;
    '') ;; # Nothing to do for plain root method.
    *)
      error "Error: unknown root authorization mechanism '$LE_AUTO_SUDO'."
      exit 1
  esac
  say "Using preset root authorization mechanism '$LE_AUTO_SUDO'."
else
  if test "`id -u`" -ne "0" ; then
    if $EXISTS sudo 1>/dev/null 2>&1; then
      SUDO=sudo
      SUDO_ENV="CERTBOT_AUTO=$0"
    else
      say \"sudo\" is not available, will use \"su\" for installation steps...
      SUDO=su_sudo
    fi
  else
    SUDO=
  fi
fi

BootstrapMessage() {
  # Arguments: Platform name
  say "Bootstrapping dependencies for $1... (you can skip this with --no-bootstrap)"
}

ExperimentalBootstrap() {
  # Arguments: Platform name, bootstrap function name
  if [ "$DEBUG" = 1 ]; then
    if [ "$2" != "" ]; then
      BootstrapMessage $1
      $2
    fi
  else
    error "FATAL: $1 support is very experimental at present..."
    error "if you would like to work on improving it, please ensure you have backups"
    error "and then run this script again with the --debug flag!"
    error "Alternatively, you can install OS dependencies yourself and run this script"
    error "again with --no-bootstrap."
    exit 1
  fi
}

DeterminePythonVersion() {
  for LE_PYTHON in "$LE_PYTHON" python2.7 python27 python2 python; do
    # Break (while keeping the LE_PYTHON value) if found.
    $EXISTS "$LE_PYTHON" > /dev/null && break
  done
  if [ "$?" != "0" ]; then
    error "Cannot find any Pythons; please install one!"
    exit 1
  fi
  export LE_PYTHON

  PYVER=`"$LE_PYTHON" -V 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`
  if [ "$PYVER" -lt 26 ]; then
    error "You have an ancient version of Python entombed in your operating system..."
    error "This isn't going to work; you'll need at least version 2.6."
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

  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='-qq'
  fi

  $SUDO apt-get $QUIET_FLAG update || error apt-get update hit problems but continuing anyway...

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
  AUGVERSION=`LC_ALL=C apt-cache show --no-all-versions libaugeas0 | grep ^Version: | cut -d" " -f2`

  if [ "$ASSUME_YES" = 1 ]; then
    YES_FLAG="-y"
  fi

  AddBackportRepo() {
    # ARGS:
    BACKPORT_NAME="$1"
    BACKPORT_SOURCELINE="$2"
    say "To use the Apache Certbot plugin, augeas needs to be installed from $BACKPORT_NAME."
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
          $SUDO apt-get $QUIET_FLAG update
        fi
      fi
    fi
    if [ "$add_backports" != 0 ]; then
      $SUDO apt-get install $QUIET_FLAG $YES_FLAG --no-install-recommends -t "$BACKPORT_NAME" $augeas_pkg
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

  $SUDO apt-get install $QUIET_FLAG $YES_FLAG --no-install-recommends \
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
    error "Neither yum nor dnf found. Aborting bootstrap!"
    exit 1
  fi

  if [ "$ASSUME_YES" = 1 ]; then
    yes_flag="-y"
  fi
  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='--quiet'
  fi

  if ! $SUDO $tool list *virtualenv >/dev/null 2>&1; then
    echo "To use Certbot, packages from the EPEL repository need to be installed."
    if ! $SUDO $tool list epel-release >/dev/null 2>&1; then
      error "Enable the EPEL repository and try running Certbot again."
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
    if ! $SUDO $tool install $yes_flag $QUIET_FLAG epel-release; then
      error "Could not enable EPEL. Aborting bootstrap!"
      exit 1
    fi
  fi

  pkgs="
    gcc
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

  if ! $SUDO $tool install $yes_flag $QUIET_FLAG $pkgs; then
    error "Could not install OS dependencies. Aborting bootstrap!"
    exit 1
  fi
}

BootstrapSuseCommon() {
  # SLE12 don't have python-virtualenv

  if [ "$ASSUME_YES" = 1 ]; then
    zypper_flags="-nq"
    install_flags="-l"
  fi

  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='-qq'
  fi

  $SUDO zypper $QUIET_FLAG $zypper_flags in $install_flags \
    python \
    python-devel \
    python-virtualenv \
    gcc \
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
    if [ "$QUIET" = 1]; then
      $SUDO pacman -S --needed $missing $noconfirm > /dev/null
    else
      $SUDO pacman -S --needed $missing $noconfirm
    fi
  fi
}

BootstrapGentooCommon() {
  PACKAGES="
    dev-lang/python:2.7
    dev-python/virtualenv
    app-admin/augeas
    dev-libs/openssl
    dev-libs/libffi
    app-misc/ca-certificates
    virtual/pkgconfig"

  ASK_OPTION="--ask"
  if [ "$ASSUME_YES" = 1 ]; then
    ASK_OPTION=""
  fi

  case "$PACKAGE_MANAGER" in
    (paludis)
      $SUDO cave resolve --preserve-world --keep-targets if-possible $PACKAGES -x
      ;;
    (pkgcore)
      $SUDO pmerge --noreplace --oneshot $ASK_OPTION $PACKAGES
      ;;
    (portage|*)
      $SUDO emerge --noreplace --oneshot $ASK_OPTION $PACKAGES
      ;;
  esac
}

BootstrapFreeBsd() {
  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG="--quiet"
  fi

  $SUDO pkg install -Ay $QUIET_FLAG \
    python \
    py27-virtualenv \
    augeas \
    libffi
}

BootstrapMac() {
  if hash brew 2>/dev/null; then
    say "Using Homebrew to install dependencies..."
    pkgman=brew
    pkgcmd="brew install"
  elif hash port 2>/dev/null; then
    say "Using MacPorts to install dependencies..."
    pkgman=port
    pkgcmd="$SUDO port install"
  else
    say "No Homebrew/MacPorts; installing Homebrew..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    pkgman=brew
    pkgcmd="brew install"
  fi

  $pkgcmd augeas
  if [ "$(which python)" = "/System/Library/Frameworks/Python.framework/Versions/2.7/bin/python" \
      -o "$(which python)" = "/usr/bin/python" ]; then
    # We want to avoid using the system Python because it requires root to use pip.
    # python.org, MacPorts or HomeBrew Python installations should all be OK.
    say "Installing python..."
    $pkgcmd python
  fi

  # Workaround for _dlopen not finding augeas on macOS
  if [ "$pkgman" = "port" ] && ! [ -e "/usr/local/lib/libaugeas.dylib" ] && [ -e "/opt/local/lib/libaugeas.dylib" ]; then
    say "Applying augeas workaround"
    $SUDO mkdir -p /usr/local/lib/
    $SUDO ln -s /opt/local/lib/libaugeas.dylib /usr/local/lib/
  fi

  if ! hash pip 2>/dev/null; then
    say "pip not installed"
    say "Installing pip..."
    curl --silent --show-error --retry 5 https://bootstrap.pypa.io/get-pip.py | python
  fi

  if ! hash virtualenv 2>/dev/null; then
    say "virtualenv not installed."
    say "Installing with pip..."
    pip install virtualenv
  fi
}

BootstrapSmartOS() {
  pkgin update
  pkgin -y install 'gcc49' 'py27-augeas' 'py27-virtualenv'
}

BootstrapMageiaCommon() {
  if [ "$QUIET" = 1 ]; then
    QUIET_FLAG='--quiet'
  fi

  if ! $SUDO urpmi --force $QUIET_FLAG \
      python \
      libpython-devel \
      python-virtualenv
    then
      error "Could not install Python dependencies. Aborting bootstrap!"
      exit 1
  fi

  if ! $SUDO urpmi --force $QUIET_FLAG \
      git \
      gcc \
      python-augeas \
      libopenssl-devel \
      libffi-devel \
      rootcerts
    then
      error "Could not install additional dependencies. Aborting bootstrap!"
      exit 1
    fi
}


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

TempDir() {
  mktemp -d 2>/dev/null || mktemp -d -t 'le'  # Linux || macOS
}



if [ "$1" = "--le-auto-phase2" ]; then
  # Phase 2: Create venv, install LE, and run.

  shift 1  # the --le-auto-phase2 arg
  if [ -f "$VENV_BIN/letsencrypt" ]; then
    # --version output ran through grep due to python-cryptography DeprecationWarnings
    # grep for both certbot and letsencrypt until certbot and shim packages have been released
    INSTALLED_VERSION=$("$VENV_BIN/letsencrypt" --version 2>&1 | grep "^certbot\|^letsencrypt" | cut -d " " -f 2)
    if [ -z "$INSTALLED_VERSION" ]; then
        error "Error: couldn't get currently installed version for $VENV_BIN/letsencrypt: " 1>&2
        "$VENV_BIN/letsencrypt" --version
        exit 1
    fi
  else
    INSTALLED_VERSION="none"
  fi
  if [ "$LE_AUTO_VERSION" != "$INSTALLED_VERSION" ]; then
    say "Creating virtual environment..."
    DeterminePythonVersion
    rm -rf "$VENV_PATH"
    if [ "$VERBOSE" = 1 ]; then
      virtualenv --no-site-packages --python "$LE_PYTHON" "$VENV_PATH"
    else
      virtualenv --no-site-packages --python "$LE_PYTHON" "$VENV_PATH" > /dev/null
    fi

    say "Installing Python packages..."
    TEMP_DIR=$(TempDir)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    # There is no $ interpolation due to quotes on starting heredoc delimiter.
    # -------------------------------------------------------------------------
    cat << "UNLIKELY_EOF" > "$TEMP_DIR/letsencrypt-auto-requirements.txt"
# This is the flattened list of packages certbot-auto installs. To generate
# this, do
# `pip install --no-cache-dir -e acme -e . -e certbot-apache -e certbot-nginx`,
# and then use `hashin` or a more secure method to gather the hashes.

# Hashin example:
# pip install hashin
# hashin -r dependency-requirements.txt cryptography==1.5.2
# sets the new certbot-auto pinned version of cryptography to 1.5.2

argparse==1.4.0 \
    --hash=sha256:c31647edb69fd3d465a847ea3157d37bed1f95f19760b11a47aa91c04b666314 \
    --hash=sha256:62b089a55be1d8949cd2bc7e0df0bddb9e028faefc8c32038cc84862aefdd6e4

# This comes before cffi because cffi will otherwise install an unchecked
# version via setup_requires.
pycparser==2.14 \
    --hash=sha256:7959b4a74abdc27b312fed1c21e6caf9309ce0b29ea86b591fd2e99ecdf27f73 \
    --no-binary pycparser

asn1crypto==0.22.0 \
    --hash=sha256:d232509fefcfcdb9a331f37e9c9dc20441019ad927c7d2176cf18ed5da0ba097 \
    --hash=sha256:cbbadd640d3165ab24b06ef25d1dca09a3441611ac15f6a6b452474fdf0aed1a
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
cryptography==1.8.2 \
    --hash=sha256:e572527dc4eae300d4ac58c3a49fd0fe1a0178baf341f536d22c45455c958410 \
    --hash=sha256:15448bcfc4ef0f58c8e049f06cb10c296d75456ced02466dff3c82cc9c85f0a6 \
    --hash=sha256:771171a4b7677ee791f74928030fb59ca83a1710d32eaec8395c5170fc520741 \
    --hash=sha256:06e47faef940bc53ca23f5c6a29f5d4ebc47f0c7632f356da8ce4cc3ae99e908 \
    --hash=sha256:730a4f2c028b33b3e6b1a3caa7a3048a1e1e6ff2fe9043acdb21b31a2e711742 \
    --hash=sha256:1bf2299033c5a517014ffd5ec2e267f6a220d9095e75dd002dc33a898a7857cc \
    --hash=sha256:5e7249bc0360d834b89631e83c1a7bbb28098b59fab9816e5e19efdef7b71a1c \
    --hash=sha256:3971bdb5054257c922d95839d10ad347dcaa7137efeed34ce33ee660ea52b7e2 \
    --hash=sha256:a8b431f82972cec974766a484eba02d7bbf6a5c042c13c25f1a23d4a3a31bfb4 \
    --hash=sha256:a9281f0292131747f94219793438d78823bb72fbcafd1b415e99af1d8c42e11c \
    --hash=sha256:502237c0ed9ca77212cf1673627fd2c361ee989cdde2ac54a0cd3f17cbc79e5a \
    --hash=sha256:c63625ec36d1615fff69b068a95ea038d5f8df961901a097dfedc7e7410794d5 \
    --hash=sha256:bda0a32d99ee1f86fcd46bbb10f43216f101df3349187ea8999967cddbfede86 \
    --hash=sha256:a4a69088671eb31aa292a5996d9dd7a4ccb585b6fc7eb7b9e47051e1169fc479 \
    --hash=sha256:0f7127b0034d5112b190de6bf46fadc41940983a91836acfdaa16c44f44beb75 \
    --hash=sha256:9049c073f86155dfcd93434d63db80f753cd2e5bebf1d6172b112de215369b07 \
    --hash=sha256:264dd80150f24a6fffb3ce5be32705e6a27160df055b3582925c2ed170f4f430 \
    --hash=sha256:a05f899c311f6810ae4981edcd23d1587be207de554cf0530f8facbe836483cb \
    --hash=sha256:91970de4b3dbf0b9b36745e9f346265d225d906188dec3d02c2179fbdb49b167 \
    --hash=sha256:908cd59ae3c177c28e7a3eb519dade45748ba9af9959796c699f4f1b56caea8d \
    --hash=sha256:f04fd7c4b7b4c0b97186f31a315fe88d20087a7148ff06a9c0348b35e39531f8 \
    --hash=sha256:757dd412a49ea396b52b051c364bf8f9262dfa6665270f68208a0d6ed5999f1b \
    --hash=sha256:7d6ab4507cf52328b27c57107491b2699a5e25097213a2d201fab0157cb5dd09 \
    --hash=sha256:e3183550d129b7103914cad049a3b2358d9405c6e4baf3a7c92a82004f5e4814 \
    --hash=sha256:9d1f63e2f4530a919ef87b4f1b3d814389604486f8b8c090aefccace4d1f98f8 \
    --hash=sha256:8e88ebac371a388024dab3ccf393bf3c1790d21bc3c299d5a6f9f83fb823beda
enum34==1.1.2 \
    --hash=sha256:2475d7fcddf5951e92ff546972758802de5260bf409319a9f1934e6bbc8b1dc7 \
    --hash=sha256:35907defb0f992b75ab7788f65fedc1cf20ffa22688e0e6f6f12afc06b3ea501
funcsigs==1.0.2 \
    --hash=sha256:330cc27ccbf7f1e992e69fef78261dc7c6569012cf397db8d3de0234e6c937ca \
    --hash=sha256:a7bb0f2cf3a3fd1ab2732cb49eba4252c2af4240442415b4abce3b87022a8f50
idna==2.5 \
    --hash=sha256:cc19709fd6d0cbfed39ea875d29ba6d4e22c0cebc510a76d6302a28385e8bb70 \
    --hash=sha256:3cb5ce08046c4e3a560fc02f138d0ac63e00f8ce5901a56b32ec8b7994082aab
ipaddress==1.0.16 \
    --hash=sha256:935712800ce4760701d89ad677666cd52691fd2f6f0b340c8b4239a3c17988a5 \
    --hash=sha256:5a3182b322a706525c46282ca6f064d27a02cffbd449f9f47416f1dc96aa71b0
linecache2==1.0.0 \
    --hash=sha256:e78be9c0a0dfcbac712fe04fbf92b96cddae80b1b842f24248214c8496f006ef \
    --hash=sha256:4b26ff4e7110db76eeb6f5a7b64a82623839d595c2038eeda662f2a2db78e97c
ordereddict==1.1 \
    --hash=sha256:1c35b4ac206cef2d24816c89f89cf289dd3d38cf7c449bb3fab7bf6d43f01b1f
packaging==16.8 \
    --hash=sha256:99276dc6e3a7851f32027a68f1095cd3f77c148091b092ea867a351811cfe388 \
    --hash=sha256:5d50835fdf0a7edf0b55e311b7c887786504efea1177abd7e69329a8e5ea619e
parsedatetime==2.1 \
    --hash=sha256:ce9d422165cf6e963905cd5f74f274ebf7cc98c941916169178ef93f0e557838 \
    --hash=sha256:17c578775520c99131634e09cfca5a05ea9e1bd2a05cd06967ebece10df7af2d
pbr==1.8.1 \
    --hash=sha256:46c8db75ae75a056bd1cc07fa21734fe2e603d11a07833ecc1eeb74c35c72e0c \
    --hash=sha256:e2127626a91e6c885db89668976db31020f0af2da728924b56480fc7ccf09649
pyOpenSSL==16.2.0 \
    --hash=sha256:26ca380ddf272f7556e48064bbcd5bd71f83dfc144f3583501c7ddbd9434ee17 \
    --hash=sha256:7779a3bbb74e79db234af6a08775568c6769b5821faecf6e2f4143edb227516e
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
requests==2.12.1 \
    --hash=sha256:3f3f27a9d0f9092935efc78054ef324eb9f8166718270aefe036dfa1e4f68e1e \
    --hash=sha256:2109ecea94df90980be040490ff1d879971b024861539abb00054062388b612e
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
mock==2.0.0 \
    --hash=sha256:5ce3c71c5545b472da17b72268978914d0252980348636840bd34a00b5cc96c1 \
    --hash=sha256:b158b6df76edd239b8208d481dc46b6afd45a846b7812ff0ce58971cf5bc8bba

# Contains the requirements for the letsencrypt package.
#
# Since the letsencrypt package depends on certbot and using pip with hashes
# requires that all installed packages have hashes listed, this allows
# dependency-requirements.txt to be used without requiring a hash for a
# (potentially unreleased) Certbot package.

letsencrypt==0.7.0 \
    --hash=sha256:105a5fb107e45bcd0722eb89696986dcf5f08a86a321d6aef25a0c7c63375ade \
    --hash=sha256:c36e532c486a7e92155ee09da54b436a3c420813ec1c590b98f635d924720de9

certbot==0.15.0 \
    --hash=sha256:f052a1ee9d0e71b73d893c26ee3aa343f6f3abe7de8471437779d541f8bf7824 \
    --hash=sha256:b8c4043b2b8df39660d4ce4a2a6eca590f98ece0e1b97eba53ab95f3bbac3beb
acme==0.15.0 \
    --hash=sha256:d423a14a8fde089d6854ccbe1314f6a80553ef06799ac6f671b90d8399835e60 \
    --hash=sha256:9fadd63322a1eb95f58e6cda8ca2095c750e828ae470bc6e3925ef618c7cfc87
certbot-apache==0.15.0 \
    --hash=sha256:07fa99b264e0ea489695cc2a5353f3fe9459422ad549de02c46da24ae546acd9 \
    --hash=sha256:6da1433381bd2c2ea7c395be57ca1bcdb7c1c04ce3d12b67a3fa207a3bfa41ca
certbot-nginx==0.15.0 \
    --hash=sha256:7b0622f8a9031e24105f9b5c8d98d4ed83ae393517ed35cc2a4fa50098122922 \
    --hash=sha256:0b98dedb22492d6f88dffdfbd721b4d4c98bfe361df35bc97bf5bd3047f01234

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
      error "Had a problem while installing Python packages."
      if [ "$VERBOSE" != 1 ]; then
        error
        error "pip prints the following errors: "
        error "====================================================="
        error "$PIP_OUT"
        error "====================================================="
        error
        error "Certbot has problem setting up the virtual environment."

        if `echo $PIP_OUT | grep -q Killed` || `echo $PIP_OUT | grep -q "allocate memory"` ; then
          error
          error "Based on your pip output, the problem can likely be fixed by "
          error "increasing the available memory."
        else
          error
          error "We were not be able to guess the right solution from your pip "
          error "output."
        fi

        error
        error "Consult https://certbot.eff.org/docs/install.html#problems-with-python-virtual-environment"
        error "for possible solutions."
        error "You may also find some support resources at https://certbot.eff.org/support/ ."
      fi
      rm -rf "$VENV_PATH"
      exit 1
    fi
    say "Installation succeeded."
  fi
  if [ -n "$SUDO" ]; then
    # SUDO is su wrapper or sudo
    say "Requesting root privileges to run certbot..."
    say "  $VENV_BIN/letsencrypt" "$@"
  fi
  if [ -z "$SUDO_ENV" ] ; then
    # SUDO is su wrapper / noop
    $SUDO "$VENV_BIN/letsencrypt" "$@"
  else
    # sudo
    $SUDO "$SUDO_ENV" "$VENV_BIN/letsencrypt" "$@"
  fi

else
  # Phase 1: Upgrade certbot-auto if necessary, then self-invoke.
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
    say "OS packages installed."
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

from __future__ import print_function

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
            print(latest_stable_version(get))
        elif flag == '--le-auto-script':
            tag = argv[2]
            verified_new_le_auto(get, tag, dirname(argv[0]))
    except ExpectedError as exc:
        print(exc.args[0], exc.args[1])
        return 1
    else:
        return 0


if __name__ == '__main__':
    exit(main())

UNLIKELY_EOF
    # ---------------------------------------------------------------------------
    DeterminePythonVersion
    if ! REMOTE_VERSION=`"$LE_PYTHON" "$TEMP_DIR/fetch.py" --latest-version` ; then
      error "WARNING: unable to check for updates."
    elif [ "$LE_AUTO_VERSION" != "$REMOTE_VERSION" ]; then
      say "Upgrading certbot-auto $LE_AUTO_VERSION to $REMOTE_VERSION..."

      # Now we drop into Python so we don't have to install even more
      # dependencies (curl, etc.), for better flow control, and for the option of
      # future Windows compatibility.
      "$LE_PYTHON" "$TEMP_DIR/fetch.py" --le-auto-script "v$REMOTE_VERSION"

      # Install new copy of certbot-auto.
      # TODO: Deal with quotes in pathnames.
      say "Replacing certbot-auto..."
      # Clone permissions with cp. chmod and chown don't have a --reference
      # option on macOS or BSD, and stat -c on Linux is stat -f on macOS and BSD:
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
