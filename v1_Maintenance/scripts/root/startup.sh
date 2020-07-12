# !/bin/bash
# Stand 2018-08-29


# IPv6 deaktivieren
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# Firewall starten
/root/firewall.sh start

# Port-Monitoring im Hintergrund starten
/root/restart_portmonitor.sh Startup
#sudo -H -u root /opt/portmonitor/tcpmonitor.sh
#sudo -H -u root /opt/portmonitor/udpmonitor.sh
#sudo -H -u root /opt/portmonitor/icmpmonitor.sh
#sleep 1
#sudo -H -u sensor /opt/portmonitor/tcppost.sh

# Fehlerprotokollierung vom Portmonitor zum Logserver schicken 
#sudo -H -u sensor tail -f /data/error.tcp.log|logger -i -t port_err_tcp_log &
#sudo -H -u sensor tail -f /data/error.udp.log|logger -i -t port_err_udp_log & 


