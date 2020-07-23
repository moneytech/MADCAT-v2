#!/bin/bash

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
