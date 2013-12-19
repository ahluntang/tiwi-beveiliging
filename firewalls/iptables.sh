#!/bin/bash

### BEGIN INFO
# Name: Iptables Configuration Script
# Author: Ah-Lun Tang <tang@ahlun.be>
# Provides: iptables configuration
# Short-Description: iptables script
### END INFO

#!/bin/bash

# External Router
EXT_INET_IFACE="eth0"
EXT_INET_IP=`ifconfig $EXT_INET_IFACE | grep 'inet addr' | awk '{print $2}' | sed -e 's/.*://'`
EXT_INET_NET="192.168.16.0/24"
EXT_INET_BCAST=`ifconfig $EXT_INET_IFACE | grep 'inet addr' | awk '{print $3}' | sed -e 's/.*://'`

EXT_DMZ_IFACE="eth1"
EXT_DMZ_ADDRESS="192.168.70.254"

# Internal Router
INT_DMZ_IFACE="eth0"
INT_DMZ_IP="192.168.70.250"

INT_LAN_IFACE="eth1"
INT_LAN_IP="10.0.0.254"
INT_LAN_NET="10.0.0.0/8"
INT_LAN_BCAST="10.0.0.255"


# DMZ AND BASTION_HOST
DMZ_NET="192.168.70.0/24"
DMZ_BCAST="192.168.70.255"
DMZ_BASTIONHOST="192.168.70.1"
DMZ_IFACE_EXT="eth1"
DMZ_IFACE_INT="eth0"




# Localhost Interface
LO_IFACE="lo"
LO_IP="127.0.0.1"

#
#
#
#  INTERNET            External Router             Bastion Host             Internal Router             Client
#  ------              -------------              ------------              -------------              -------
# |      |------------| eth0 | eth1 |------------|   bridge   |------------| eth0 | eth1 |------------|       |
#  ------              -------------              ------------              -------------              -------
#
#
dropcurrentconfig() {
    # Flush all rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F

    # Erase all non-default chains
    iptables -X
    iptables -t nat -X
    iptables -t mangle -X

}

accept_policy(){
    # Reset Default Accept Policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
}

drop_policy(){
    # Reset Default Drop Policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
}

logging(){
    # drop all traffic from/to unknown/invalid connections
    iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "Invalid input packet: "
    iptables -A INPUT -m state --state INVALID -j DROP

    iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Invalid forward packet: "
    iptables -A FORWARD -m state --state INVALID -j DROP

    iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "Invalid output packet: "
    iptables -A OUTPUT -m state --state INVALID -j DROP
}

enable_forwarding(){
	# Enable IPv4 Forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
}

local_traffic(){
    # Prevent Freezes
    iptables -I INPUT -d $LO_IP -j ACCEPT
    iptables -I OUTPUT -s $LO_IP -j ACCEPT
}


external_router() {
    # Allow rip (UDP/520, RIPng: UPD/521)
    iptables -I INPUT -i $EXT_INET_IFACE -p udp --dport router -j ACCEPT
    iptables -I OUTPUT -o $EXT_INET_IFACE -p udp --sport router -j ACCEPT
    iptables -I INPUT -i $EXT_INET_IFACE -p udp --dport ripng -j ACCEPT
    iptables -I OUTPUT -o $EXT_INET_IFACE -p udp --sport ripng -j ACCEPT

    iptables -I INPUT -p igmp -j ACCEPT
    iptables -I OUTPUT -p igmp -j ACCEPT
    iptables -I FORWARD -p igmp -j ACCEPT

    # Allow ESP
    iptables -I FORWARD -p esp -j ACCEPT

    # Allow AH
    iptables -I FORWARD -p ah -j ACCEPT

    # Allow internet to access http server in dmz
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_NET -p tcp --dport http -j ACCEPT
    iptables -I FORWARD -s $DMZ_NET -o $EXT_INET_IFACE -p tcp --sport http -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow internet to access dns server in dmz
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_NET -p udp --dport domain -j ACCEPT
    iptables -I FORWARD -s $DMZ_NET -o $EXT_INET_IFACE -p udp --sport domain -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow internet to access smtp server in dmz
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_NET -p tcp --dport smtp -j ACCEPT
    iptables -I FORWARD -s $DMZ_NET -o $EXT_INET_IFACE -p tcp --sport smtp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_NET -p tcp --dport submission -j ACCEPT
    iptables -I FORWARD -s $DMZ_NET -o $EXT_INET_IFACE -p tcp --sport submission -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow bastion host to access ssh server from internet
    iptables -I FORWARD -s $DMZ_BASTIONHOST -o $EXT_INET_IFACE -p tcp --dport ssh -j ACCEPT
    iptables -I FORWARD -s $DMZ_BASTIONHOST -o $EXT_INET_IFACE -p tcp --dport ssh -j LOG --log-prefix "Secure Shell: "
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_BASTIONHOST -p tcp --sport ssh -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow bastion host to access http server from internet
    iptables -I FORWARD -s $DMZ_BASTIONHOST -o $EXT_INET_IFACE -p tcp --dport http -j ACCEPT
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_BASTIONHOST -p tcp --sport http -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow bastion host to access dns server from internet
    iptables -I FORWARD -s $DMZ_BASTIONHOST -o $EXT_INET_IFACE -p udp --dport domain -j ACCEPT
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_BASTIONHOST -p udp --sport domain -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # Allow bastion host to access mail server from internet
    iptables -I FORWARD -s $DMZ_BASTIONHOST -o $EXT_INET_IFACE -p tcp --dport smtp -j ACCEPT
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_BASTIONHOST -p tcp --sport smtp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -I FORWARD -s $DMZ_BASTIONHOST -o $EXT_INET_IFACE -p tcp --dport submission -j ACCEPT
    iptables -I FORWARD -i $EXT_INET_IFACE -d $DMZ_BASTIONHOST -p tcp --sport submission -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

internal_router(){
    # Allow ICMP from LAN to DMZ 
    iptables -I INPUT -p icmp -s $DMZ_NET -j ACCEPT
    iptables -I INPUT -p icmp -s $INT_LAN_NET -j ACCEPT
    iptables -I FORWARD -p icmp -s $DMZ_NET -j ACCEPT
    iptables -I FORWARD -p icmp -s $INT_LAN_NET -j ACCEPT
    iptables -I OUTPUT -p icmp -d $DMZ_NET -j ACCEPT
    iptables -I OUTPUT -p icmp -d $INT_LAN_NET -j ACCEPT

    # Allow DNS traffic to Bastion Host
    iptables -I FORWARD -p udp -d $DMZ_BASTIONHOST --dport domain -j ACCEPT
    iptables -I FORWARD -p udp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport domain -j ACCEPT

    # Allow HTTP traffic to Bastion Host
    iptables -I FORWARD -p tcp -d $DMZ_BASTIONHOST --dport http -j ACCEPT
    iptables -I FORWARD -p tcp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport http -j ACCEPT

    # Allow SSH traffic to Bastion Host
    iptables -I FORWARD -p tcp -d $DMZ_BASTIONHOST --dport ssh -j ACCEPT
    iptables -I FORWARD -p tcp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport ssh -j ACCEPT

    # Allow MAIL traffic to Bastion Host
    iptables -I FORWARD -p tcp -d $DMZ_BASTIONHOST --dport smtp -j ACCEPT
    iptables -I FORWARD -p tcp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport smtp -j ACCEPT
    iptables -I FORWARD -p tcp -d $DMZ_BASTIONHOST --dport submission -j ACCEPT
    iptables -I FORWARD -p tcp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport submission -j ACCEPT
    iptables -I FORWARD -p tcp -d $DMZ_BASTIONHOST --dport pop3 -j ACCEPT
    iptables -I FORWARD -p tcp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport pop3 -j ACCEPT
    iptables -I FORWARD -p tcp -d $DMZ_BASTIONHOST --dport imap -j ACCEPT
    iptables -I FORWARD -p tcp -s $DMZ_BASTIONHOST -m conntrack --ctstate ESTABLISHED,RELATED --sport imap -j ACCEPT
}

init_bridge(){
    ifconfig $DMZ_IFACE_EXT 0.0.0.0 up
    ifconfig $DMZ_IFACE_INT 0.0.0.0 up
    brctl addbr br0
    brctl stp br0 on # prevent switching loops
    brctl addif br0 $DMZ_IFACE_EXT
    brctl addif br0 $DMZ_IFACE_INT
    ifconfig br0 $DMZ_BASTIONHOST up
}

reject_undefined(){
    iptables -A INPUT -j REJECT
    iptables -A OUTPUT -j REJECT
    iptables -A FORWARD -j REJECT
}

case $1 in
    external)
        echo "Setting up iptables for external router ... "
        dropcurrentconfig   &&  echo " -> IPTable configuration flushed."
        accept_policy       &&  echo " -> IPTable default accept policy."
        enable_forwarding   &&  echo " -> Enable IPv4 forwarding."
        local_traffic       &&  echo " -> Enable local traffic (to prevent freezes)"
        external_router     &&  echo " -> Setting up external router."
        reject_undefined    &&  echo " -> Reject undefined."
    ;;
    internal)
        echo "Setting up iptables for internal router ... "
        dropcurrentconfig   &&  echo " -> IPTable configuration flushed."
        accept_policy       &&  echo " -> IPTable default accept policy."
        enable_forwarding   &&  echo " -> Enable IPv4 forwarding."
        local_traffic       &&  echo " -> Enable local traffic (to prevent freezes)"
        internal_router     &&  echo " -> Setting up internal router."
        reject_undefined    &&  echo " -> Reject undefined."
    ;;
    bastion)
        echo "Setting up bridge for bastion host ... "
        init_bridge         &&  echo " -> Setting up bridge."
    ;;
    flush)
        echo "Drop current configuration..."
        dropcurrentconfig   &&  echo " -> IPTable configuration flushed."
    ;;
    reset)
        echo "Drop current configuration..."
        dropcurrentconfig   &&  echo " -> IPTable configuration flushed."
        acceptpolicy        &&  echo " -> Accept policy enabled."
    ;;
    *)
        echo "usage: $0 external|internal|bastion|reset|flush"
        exit 1
    ;;
esac

exit 0