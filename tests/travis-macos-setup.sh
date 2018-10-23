#!/bin/bash -e
#
# Set up the test environment for macOS on Travis.

# Install the given package with brew if it's not already installed.
brew_install() {
    if ! brew list "$1" > /dev/null 2>&1; then
        brew install "$1"
    fi
}

brew_install augeas
brew_install python
brew_install python3

# Ensure we use python from brew.
brew link python
