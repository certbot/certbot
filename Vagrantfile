# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

# Setup instructions from docs/contributing.rst
$ubuntu_setup_script = <<SETUP_SCRIPT
cd /vagrant
./bootstrap/install-deps.sh
./bootstrap/dev/venv.sh
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
    end
  end

end
