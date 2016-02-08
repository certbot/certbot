#!/bin/sh -e
if ! hash brew 2>/dev/null; then
    echo "Homebrew Not Installed\nDownloading..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

brew --prefix augeas &>/dev/null || brew install augeas
brew --prefix dialog &>/dev/null || brew install dialog

if ! hash pip 2>/dev/null; then
    echo "pip Not Installed\nInstalling python from Homebrew..."
    brew install python
fi

if ! pip list | grep 'virtualenv\s' &>/dev/null then
    echo "virtualenv Not Installed\nInstalling with pip"
    pip install virtualenv
fi
