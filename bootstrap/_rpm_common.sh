#!/bin/sh

# Tested with:
#   - Fedora 22 (x64)
#   - Centos 7 (x64: on AWS EC2 t2.micro, DigitalOcean droplet)

# "git-core" seems to be an alias for "git" in CentOS 7 (yum search fails)
bootstrap() {

    pkgs="git-core
        python 
        python-devel 
        python-virtualenv 
        python-devel 
        gcc dialog 
        augeas-libs 
        openssl-devel 
        libffi-devel 
        ca-certificates"

    if hash yum 2>/dev/null; then
      yum install -y $pkgs;

    elif hash dnf 2>/dev/null; then
      dnf install -y $pkgs;

    else
      echo "Neither yum nor dnf found. Aborting bootstrap!"
      exit 1;

    fi
}
bootstrap
