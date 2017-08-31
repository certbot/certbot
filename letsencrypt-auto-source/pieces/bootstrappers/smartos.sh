# If new packages are installed by BootstrapSmartOS below, this version number
# must be increased.
BOOTSTRAP_SMARTOS_VERSION=1

BootstrapSmartOS() {
  pkgin update
  pkgin -y install 'gcc49' 'py27-augeas' 'py27-virtualenv'
}
