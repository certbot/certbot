#!/bin/sh

# Tested with:
# - CentOS 6.7 (x64)


if [ `lsb_release -rs | cut -f1 -d.` -eq 6 ]
then
	# Setup SCL Repo - https://wiki.centos.org/AdditionalResources/Repositories/SCL
	yum -y install centos-release-SCL

	# Now install Deps
	yum -y install \
		git-core \
		python27 \
		python27-python-devel \
		python27-python-virtualenv  \
		gcc \
		dialog \
		augeas-libs \
		openssl-devel \
		libffi-devel \
		ca-certificates

else
	source $BOOTSTRAP/_rpm_common.sh
fi
