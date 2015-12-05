#!/bin/sh -e
OSX_PM_="no_package_manager" # OS X Package Manager
if hash port 2>/dev/null; then
    OSX_PM_="sudo port"
elif hash brew 2>/dev/null; then
    OSX_PM_="brew"
elif ! hash brew 2>/dev/null; then
    echo "Homebrew Not Installed\nDownloading..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    OSX_PM_="brew"
fi

${OSX_PM_} install augeas
${OSX_PM_} install dialog

if ! hash pip 2>/dev/null; then
    if [ "${OSX_PM_}" == "sudo port" ]; then
      echo "pip Not Installed\nInstalling python from Mac Ports ..."
      ${OSX_PM_} install python27
    else
      echo "pip Not Installed\nInstalling python from Homebrew..."
      ${OSX_PM_} install python
    fi
fi

if ! hash virtualenv 2>/dev/null; then
    echo "virtualenv Not Installed\nInstalling with pip"
    pip install virtualenv
fi
