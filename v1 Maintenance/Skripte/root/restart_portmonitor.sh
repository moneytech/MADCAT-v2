#!/bin/bash

PIDDIR="/var/run/madcat"
if [ ! -d "$PIDDIR" ]; then
        mkdir $PIDDIR
fi
chmod 777 "$PIDDIR"
####################
echo kill running MADCAT Processes
/root/stop_portmonitor.sh
#####################
echo start portmonitoring
sudo -H -u root /opt/portmonitor/tcpmonitor.sh
sleep 1
sudo -H -u sensor /opt/portmonitor/tcppost.sh
sudo -H -u root /opt/portmonitor/udpmonitor.sh
sudo -H -u root /opt/portmonitor/icmpmonitor.sh
######################
echo restart filebeat
systemctl restart filebeat
######################
######################
echo start watchdog
/bin/bash /opt/portmonitor/watchdog.sh 0<&- &>/dev/null &
######################
######################
echo log last restart
echo "$(date) Last execution of $0. Arguments: $*." >>/data/error.restart.log
######################
exit 0
