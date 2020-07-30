# !/bin/bash
# Stand 2019-02-25

firewall_start()  {
echo "$0: starting firewall"

EXTERN="enx0008bbfd8a82"
INTERN="enp2s0"
EXTERNE_IP="192.168.22.150"
Netzv4_MNGT="172.16.168.0/21"
Remote_Host_A="192.168.116.16"
Remote_Host_B="192.168.116.116"
HOSTv4_NTP="192.168.113.1"
HOSTv4_DNS="192.168.120.9"
HOSTv4_SSH="192.168.110.0/24"

iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t nat -X
iptables -t mangle -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# ++++++++++++++  invalid incoming +++++++++++++++++++++
#iptables -A INPUT -m state --state INVALID -j DROP
# NEW and no SYN flag
#iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
# no flags
#iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# SYN and FIN is set
#iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
# SYN and RST is set
#iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# FIN and RST is set
#iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
# FIN without ACK
#iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
# PSH without ACK
#iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
# URG without ACK
#iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

# ++++++++++++++  invalid outgoing +++++++++++++++++++++
iptables -A OUTPUT -o $INTERN -m state --state INVALID -j DROP

# NTP Update
iptables -A OUTPUT -o $INTERN -d $HOSTv4_NTP -m state --state NEW -p udp --dport 123 -j LOG --log-prefix "pf_basis:accept:" --log-level 5 
iptables -A OUTPUT -o $INTERN -d $HOSTv4_NTP -m state --state NEW,ESTABLISH,RELATED -p udp --dport 123 -j ACCEPT
iptables -A INPUT -i $INTERN -s $HOSTv4_NTP -m state --state ESTABLISH,RELATED -p udp --sport 123 -j ACCEPT

# SSH-Zugriff
iptables -A OUTPUT -o $INTERN -d $HOSTv4_SSH -m state --state ESTABLISH,RELATED -p tcp --sport 22 -j ACCEPT
iptables -A INPUT -i $INTERN -s $HOSTv4_SSH -m state --state NEW -p tcp --dport 22 -j LOG --log-prefix "pf_mngt:accept:" --log-level 5
iptables -A INPUT -i $INTERN -s $HOSTv4_SSH -m state --state NEW,ESTABLISH,RELATED -p tcp --dport 22 -j ACCEPT

# Remote TLS Syslog
iptables -A OUTPUT -o $INTERN -d $Remote_Host_A -m state --state NEW -p tcp --dport 1999 -j LOG --log-prefix "pf_basis:accept:" --log-level 5 
iptables -A OUTPUT -o $INTERN -d $Remote_Host_A -m state --state NEW,ESTABLISH,RELATED -p tcp --dport 1999 -j ACCEPT
iptables -A INPUT -i $INTERN -s $Remote_Host_A -m state --state ESTABLISH,RELATED -p tcp --sport 1999 -j ACCEPT

# Remote Filebeat (ELK-Stack) 
iptables -A OUTPUT -o $INTERN -d $Remote_Host_B -m state --state NEW -p tcp --dport 5044 -j LOG --log-prefix "pf_basis:accept:" --log-level 5 
iptables -A OUTPUT -o $INTERN -d $Remote_Host_B -m state --state NEW,ESTABLISH,RELATED -p tcp --dport 5044 -j ACCEPT
iptables -A INPUT -i $INTERN -s $Remote_Host_B -m state --state ESTABLISH,RELATED -p tcp --sport 5044 -j ACCEPT

# NAT fuer Port-Monitor
iptables -t nat -A PREROUTING -i $EXTERN -p tcp --dport 1:65534 -j DNAT --to 192.168.22.150:65535

if [ $# -eq 1 ]; then
  if [ $1 = "update" ]; then
    # Port 80 fuer HTTP erlauben (apt-get)
    iptables -A OUTPUT -o $INTERN -p tcp  --dport 80 -m state --state NEW -j LOG --log-prefix "pf_basis:accept:" --log-level 5 
    iptables -A OUTPUT -o $INTERN -p tcp  --dport 80 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i $INTERN -p tcp  --sport 80 -m state --state ESTABLISHED,RELATED -j ACCEPT
   fi
fi

# Port-Monitor (verboten)
iptables -A OUTPUT -o $EXTERN -m state --state NEW -j LOG --log-prefix "pf_OUTPUT:sensor_extern_drop:" --log-level 7
iptables -A OUTPUT -o $EXTERN -m state --state NEW -j DROP 

# Port-Monitor (erlaubt)
iptables -A OUTPUT -o $EXTERN -p tcp -j  ACCEPT
iptables -A OUTPUT -o $EXTERN -p udp -j  ACCEPT
iptables -A OUTPUT -o $EXTERN -p ICMP -j  ACCEPT
iptables -A INPUT -i $EXTERN -p tcp -j ACCEPT
iptables -A INPUT -i $EXTERN -p udp -j ACCEPT
iptables -A INPUT -i $EXTERN -p ICMP -j ACCEPT

# Port-Monitor (verboten)
iptables -A OUTPUT -o $INTERN -m state --state NEW -j LOG --log-prefix "pf_OUTPUT:sensor_intern_drop:" --log-level 7
iptables -A OUTPUT -o $INTERN -m state --state NEW -j DROP 

# Ansonsten INPUT und OUTPUT alles blockieren und protokollieren

iptables -A INPUT -j LOG --log-prefix "pf_INPUT:all_end_drop:" --log-level 4
iptables -A INPUT -j DROP
iptables -A OUTPUT -j LOG --log-prefix "pf_OUTPUT:all_end_drop:" --log-level 4
iptables -A OUTPUT -j DROP
iptables -A FORWARD -j LOG --log-prefix "pf_FORWARD:all_end_drop:" --log-level 4
iptables -A FORWARD -j DROP
}


firewall_stop() {
echo "$0: stopping firewall"
   
iptables -F
iptables -t mangle -F
iptables -X
iptables -t mangle -X
iptables -t nat -F

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

}

# firewall test mode
firewall_test() {
   echo "$0: starting firewall for 20 seconds"
   $0 start
   sleep 20
   $0 stop
}

# restart firwall
firewall_restart()  {
   echo "$0: restarting firewall"
   $0 stop
   $0 start   
}

# display firewall rules
firewall_status() {
   echo "$0: firewall status"
   iptables -L -vn
   #iptables -t nat -L
}

# display firewall rules
firewall_status_nat() {
   echo "$0: NAT status"
   iptables -t nat -L
}


# only NAT
firewall_nat() {
   echo "$0: only NAT"
   iptables -t nat -A PREROUTING -i enx0008bbfd8a82 -p tcp --dport 1:65534 -j DNAT --to 192.168.22.150:65535
   iptables -t nat -L
}

case "$1" in
start)
   firewall_start
   exit 0
;;

stop)
   firewall_stop      
   exit 0
;;

test)
   firewall_test
   exit 0
;;

restart)        
   firewall_restart
   exit 0
;;

status)
   firewall_status
   exit 0
;;

status_nat)
   firewall_status_nat
   exit 0
;;

nat)
   firewall_nat
   exit 0
;;


update)
   firewall_stop
   firewall_start update
   echo "Updates koennen durchgefuehrt werden"
   echo "Nach den Updates >restart< durchfuehren:" 
   exit 0
;;

*)
   echo "$0: iptables Firewall"
   echo "$0: { start | stop | restart | status | status_nat | nat | test | update }"
   exit 0
;;
esac


