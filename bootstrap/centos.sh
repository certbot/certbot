#!/bin/sh

# Tested with:
# - CentOS 6.7 (x64)


if [ `lsb_release -rs | cut -f1 -d.` -eq 6 ]
then
    
    if [[ ! -f /etc/yum.repos.d/ius.repo || ! -f /usr/bin/python2.7 ]] ; then
    
        # Setup SCL Repo - https://wiki.centos.org/AdditionalResources/Repositories/SCL	
        yum -y install centos-release-SCL
		# Disable SCL
        sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/CentOS-SCL.repo
    	
        # Install Python 2.7
        yum -y --enablerepo=scl install \
            python27 \
            python27-python-devel \
            python27-python-virtualenv
    fi 
        # Now install Deps
    yum -y install \
        git-core \
        gcc \
        dialog \
        augeas-libs \
        openssl-devel \
        libffi-devel \
        ca-certificates
    else
    source $BOOTSTRAP/_rpm_common.sh
fi
