#!/bin/sh -e
if ! hash brew 2>/dev/null; then
    echo "Homebrew Not Installed\nDownloading..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

if [ -z "$(brew list --versions augeas)" ]; then
    echo "augeas Not Installed\nInstalling augeas from Homebrew..."
    brew install augeas
fi

if [ -z "$(brew list --versions dialog)" ]; then
    echo "dialog Not Installed\nInstalling dialog from Homebrew..."
    brew install dialog
fi

if ! hash pip 2>/dev/null; then
    echo "pip Not Installed\nInstalling python from Homebrew..."
    brew install python
fi

if ! hash virtualenv 2>/dev/null; then
    echo "virtualenv Not Installed\nInstalling with pip"
    pip install virtualenv
fi
