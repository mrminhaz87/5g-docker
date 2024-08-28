## Config:

4 Core, 8GB Ram,
IP: 192.168.40.100

## install-5g.sh:
```shell
#! /bin/bash

echo "Updating the repository"
apt update
echo "Installing git"
apt-get install git -y

echo "Downloading and installing caldera"
# apt-get update
apt-get install python3 -y 
apt-get install ansible -y

git clone https://github.com/abdulazizag/Virtual-Machine-and-Container-based-Deployment-of-5G-using-Ansible-with-Security-Implementation.git
cd Virtual-Machine-and-Container-based-Deployment-of-5G-using-Ansible-with-Security-Implementation
cd Docker\ Deployment\ with\ IPsec
sed -i 's/ubuntu {{ansible_distribution_release}} edge/ubuntu focal stable/' Ansible_5G_deployment.yml
echo "Running Ansible_5G_deployment.yml with network_interface=eth1"
ansible-playbook -K Ansible_5G_deployment.yml -e "internet_network_interface=eth1"

```
## 
```shell
docker exec -it ue bash

git clone https://github.com/mrminhaz87/5g-docker
sudo apt update && sudo apt install python3-pip
pip3 install --upgrade pip
pip3 install scapy cryptography
```

## 
```shell
sudo docker exec ue python3 IPSec_enc.py
sudo docker exec ue python3 Web_Analyzer.py



```



## 
```shell

```