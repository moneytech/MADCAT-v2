# !/bin/bash
# Stand 2019-02-25
#*******************************************************************************
# This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
#    MADCAT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    MADCAT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
#
#    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
#    MADCAT ist Freie Software: Sie können es unter den Bedingungen
#    der GNU General Public License, wie von der Free Software Foundation,
#    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
#    veröffentlichten Version, weiter verteilen und/oder modifizieren.
#    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
#    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
#    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
#    Siehe die GNU General Public License für weitere Details.
#    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
#    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
#*******************************************************************************/
#
#Detlef Nuß, Heiko Folkerts, BSI 2018-2020
#

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


