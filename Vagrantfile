# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

# Setup instructions from docs/contributing.rst
# Script installs dependencies for tox and boulder integration
$ubuntu_setup_script = <<SETUP_SCRIPT
cd /vagrant
./letsencrypt-auto-source/letsencrypt-auto --os-packages-only
./tools/venv.sh
wget https://storage.googleapis.com/golang/go1.5.3.linux-amd64.tar.gz -P /tmp/
sudo tar -C /usr/local -xzf /tmp/go1.5.3.linux-amd64.tar.gz
if ! grep -Fxq "export GOROOT=/usr/local/go" /home/vagrant/.profile ; then echo "export GOROOT=/usr/local/go" >> /home/vagrant/.profile; fi
if ! grep -Fxq "export PATH=\\$GOROOT/bin:\\$PATH" /home/vagrant/.profile ; then echo "export PATH=\\$GOROOT/bin:\\$PATH" >> /home/vagrant/.profile; fi
if ! grep -Fxq "export GOPATH=\\$HOME/go" /home/vagrant/.profile ; then echo "export GOPATH=\\$HOME/go" >> /home/vagrant/.profile; fi
if ! grep -Fxq "cd /vagrant/; ./tests/boulder-start.sh &" /etc/rc.local ; then sed -i -e '$i \cd /vagrant/; ./tests/boulder-start.sh &\n' /etc/rc.local; fi
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get -q -y install git make libltdl-dev mariadb-server rabbitmq-server nginx-light
SETUP_SCRIPT

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.define "ubuntu-trusty", primary: true do |ubuntu_trusty|
    ubuntu_trusty.vm.box = "ubuntu/trusty64"
    ubuntu_trusty.vm.provision "shell", inline: $ubuntu_setup_script
    ubuntu_trusty.vm.provider "virtualbox" do |v|
      # VM needs more memory to run test suite, got "OSError: [Errno 12]
      # Cannot allocate memory" when running
      # letsencrypt.client.tests.display.util_test.NcursesDisplayTest
      v.memory = 1024

      # Handle cases when the host is behind a private network by making the 
      # NAT engine use the host's resolver mechanisms to handle DNS requests.
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    end
  end

end
