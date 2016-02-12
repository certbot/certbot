BootstrapMac() {
  if ! hash brew 2>/dev/null; then
      echo "Homebrew not installed.\nDownloading..."
      ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
  fi

  if [ -z "$(brew list --versions augeas)" ]; then
      echo "augeas not installed.\nInstalling augeas from Homebrew..."
      brew install augeas
  fi

  if [ -z "$(brew list --versions dialog)" ]; then
      echo "dialog not installed.\nInstalling dialog from Homebrew..."
      brew install dialog
  fi

  if ! hash pip 2>/dev/null; then
      echo "pip not installed.\nInstalling python from Homebrew..."
      brew install python
  fi

  if ! hash virtualenv 2>/dev/null; then
      echo "virtualenv not installed.\nInstalling with pip..."
      pip install virtualenv
  fi
}
