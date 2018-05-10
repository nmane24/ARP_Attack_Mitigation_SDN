# Project – ARP attack mitigation in Software defined networking

Introduction – 
ARP spoofing is a common attack observed in LAN network. It is layer-2 attack, thus affecting upper layers of network stack as well. This makes ARP attack detection and mitigation necessary in LAN network.
In this project, topology has been created using mininet. The topology consists of one SDN controller (Ryu), one OvsSwitch and four hosts connected to single switch. 
Among four hosts, one host acts as a DHCP server. One host act as an attacker which tries to poison the ARP cache of another host.

Requirements – 
Install Mininet –
Import Mininet on Virtual Box and install required dependencies 

Update repo:
“ sudo apt-get update ”

Install dependencies:
“ sudo apt-get install git”
“ sudo apt-get install build-essential ant maven python-dev “
“ sudo apt-get install python-pip ”

Install mininet in Ubuntu as follows: 
“ git clone git://github.com/mininet/mininet ”
“ cd mininet “
“ git tag ”   -   This step should list mininet version available : 2.2.2 , 2.2.1 etc. If 2.2.2 is available then install 2.2.2 else install 2.2.1
“ git checkout -b 2.2.2 ”
“ cd .. ” : to go one step back into directory tree.
“ mininet/util/install.sh -a” 
“ sudo mn --test pingall ” : To test if mininet is successfully installed. Output should look similar to below screenshot
“ sudo mn -c ” : to clear the topology created

Install RYU 
Step 1: Install tools
sudo apt-get -y install git python-pip python-dev

Step 2 : install python packages
sudo apt-get -y install python-eventlet python-routes python-webob python-paramiko

step 3:Clone RYU repo from git
git clone https://github.com/osrg/ryu.git
sudo pip install setuptools --upgrade
 cd ryu/
~/ryu→ sudo pip install -r tools/pip-requires
~/ryu-> sudo apt install gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
~/ryu-> sudo pip install -U netaddr six pbr
~/ryu -> sudo python ./setup.py install

step 4: Install and upgrade python packages
~/ryu -> sudo pip install six --upgrade
~/ryu -> sudo pip install oslo.config msgpack-python
~/ryu -> sudo pip install eventlet –upgrade

After installation of Ryu, copy ‘arp_attck_mitigation.py’ to following location – 
“Ryu/ryu/app/   “ 


Install DHCP server

>>> sudo apt-get update
>>> sudo apt-get install isc-dhcp-server

Modify dhcp.conf file:
>>> sudo nano -w /etc/dhcp/dhcpd.conf

Place the below lines of code into the file
# A slightly different configuration for an internal subnet.    
 subnet 10.0.0.0 netmask 255.255.255.0 {    
    range 10.0.0.0 10.0.0.30;    
    option domain-name-servers 8.8.8.8, 8.8.4.4;    
    \#  option domain-name "internal.example.org";    
    option routers 10.0.0.254;    
    option broacast-address 10.0.0.255;    
    default-lease-time 600;    
    max-lease-time 7200;}






Implementation –

Create topology on mininet – 
sudo mn --topo single,4 --mac --controller=remote,ip=[IP ADDRESS OF CONTROLLER] --switch ovsk,protocols=OpenFlow13

This will create a topology with 4 hosts connected to single switch.

Start Ryu application – 

>> ryu-manger simple arp_attack_mitigation.py


Run DHCP server and client commands –
We have configured Host H1 as DHCP server. 
Enter following command on mininet to open terminal for h1 –
Mininet> xterm h1

Enter following commands on h1 terminal to start DHCP service–
  h1>>  echo 1 > /proc/sys/net/ipv4/ip_forward
  h1>> service isc-dhcp-server restart &

Enter following command on each host to get IP address assigned by DHCP server –
  h2>> ifconfig h2-eth0 0
  h2>> dhclient h2-eth0
Enter same commands for h3 and h4 as well 

Run Attack code from h2 – 
To run ARP spoofing attack from h2, enter – 
 h2>> python arp_attack.py

To run ARP flood attack from h2, enter –
 h2>> python arp_flood_attack.py

