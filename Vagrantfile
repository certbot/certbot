# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # All Vagrant configuration is done here. The most common configuration
  # options are documented and commented below. For a complete reference,
  # please see the online documentation at vagrantup.com.

  # Every Vagrant virtual environment requires a box to build off of.
  config.vm.box = "hashicorp/precise32"

  config.vm.define "sender" do |sender|
    sender.vm.network "private_network", ip: "192.168.33.5"
  end
  config.vm.define "valid" do |valid|
    valid.vm.network "private_network", ip: "192.168.33.7"
  end
  config.vm.provision :shell, path: "vagrant-bootstrap.sh"

  config.vm.provider "virtualbox" do |vb|
 #   vb.gui = true
     vb.customize ["modifyvm", :id, "--memory", "256"]
  end
end
