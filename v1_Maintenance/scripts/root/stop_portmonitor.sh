#!/bin/bash
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

######################
# remove pid-files to stop watchdog and let him time to recognize
rm /var/run/madcat/*
sleep 5
####################
# kill process  tcp_pot_mon
pid=$(pidof tcp_ip_port_mon)
kill -9 $pid && echo tcp_ip_port_mon killed
####################
# kill process udp_pot_mon
pid=$(pidof udp_ip_port_mon)
kill -9 $pid && echo udp_ip_port_mon killed
####################
# kill process icmp_mon
pid=$(pidof icmp_mon)
kill -9 $pid && echo icmp_mon killed
#####################
# delete Log-file
rm /data/portmonitor.log
#####################
# stop filebeat
systemctl stop filebeat
######################
exit 0
