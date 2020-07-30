# !/bin/bash
# Stand 2018-08-29
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


