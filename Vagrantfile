$script = <<SCRIPT
apt update
apt -y upgrade

# install all needed packages
apt install -y python3 rabbitmq-server amqp-tools make git 

# enable rabbitmq cli tools
rabbitmq-plugins enable rabbitmq_management

# set rabbitmq user, vhost and queue
rabbitmqctl add_vhost antivirus
rabbitmqctl add_user mwiesner geheim
rabbitmqctl set_permissions -p antivirus mwiesner ".*" ".*" ".*"
rabbitmqctl set_user_tags mwiesner administrator
rabbitmqadmin declare queue --vhost=antivirus name=scan_file durable=true -u mwiesner -p geheim
rabbitmqadmin declare queue --vhost=antivirus name=scan_url durable=true -u mwiesner -p geheim

# install antivirus service
cd /vagrant
make install

# Start develop webserver
echo 'python3 /vagrant/develop_webserver.py 7001'

# the services should run, check status by:
echo 'systemctl status antivirus-webserver'
echo 'systemctl status antivirus-scanurl'
echo 'systemctl status antivirus-scanfile'
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "debian/stretch64"

  config.vm.define "servicehost" do |master|
    master.vm.network :private_network, ip: "192.168.2.1"
    master.vm.network "forwarded_port", guest: 15672, host: 15672
  end

  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  config.vm.provision "shell", inline: $script
end