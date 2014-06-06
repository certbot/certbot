# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "hashicorp/precise32"

  config.vm.define "sender" do |sender|
    sender.vm.network "private_network", ip: "192.168.33.5"
    sender.vm.hostname = "sender.example.com"
    config.vm.synced_folder "vm-postfix-config-sender", "/etc/postfix"
  end
  config.vm.define "valid" do |valid|
    valid.vm.network "private_network", ip: "192.168.33.7"
    valid.vm.hostname = "valid-example-recipient.com"
    config.vm.synced_folder "vm-postfix-config-valid", "/etc/postfix"
  end
  config.vm.provision :shell, path: "vagrant-bootstrap.sh"

  config.vm.provider "virtualbox" do |vb|
 #   vb.gui = true
     vb.customize ["modifyvm", :id, "--memory", "256"]
  end

end
