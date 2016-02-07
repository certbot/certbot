#!/bin/sh -e
if ! hash brew 2>/dev/null; then
    echo "Homebrew Not Installed\nDownloading..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

brew install augeas
brew install dialog
brew install python

if ! hash virtualenv 2>/dev/null; then
    echo "virtualenv Not Installed\nInstalling with pip"
    pip install virtualenv
fi
