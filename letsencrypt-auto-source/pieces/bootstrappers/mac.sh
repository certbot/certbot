BootstrapMac() {
  if ! hash brew 2>/dev/null; then
      echo "Homebrew Not Installed\nDownloading..."
      ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
  fi

  brew install augeas
  brew install dialog

  if ! hash pip 2>/dev/null; then
      echo "pip Not Installed\nInstalling python from Homebrew..."
      brew install python
  fi

  if ! hash virtualenv 2>/dev/null; then
      echo "virtualenv Not Installed\nInstalling with pip"
      pip install virtualenv
  fi
}
