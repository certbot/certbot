#!/bin/sh -e
if ! hash brew 2>/dev/null; then
    echo "Homebrew Not Installed\nDownloading..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
fi

brew install augeas
brew install dialog

if ! hash pip 2>/dev/null; then
    echo "pip Not Installed. Downloading..."
    curl -so get-pip.py 'https://bootstrap.pypa.io/get-pip.py'
    echo sudo python get-pip.py
    sudo python get-pip.py
    rm get-pip.py
fi

if ! hash virtualenv 2>/dev/null; then
    echo "virtualenv Not Installed\nInstalling with pip"
    echo sudo pip install virtualenv
    sudo pip install virtualenv
fi
