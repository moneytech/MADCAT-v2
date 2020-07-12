# !/bin/bash
# Stand 2019-02-25
#/opt/portmonitor/udp_port_mon 192.168.22.150 /data/ sensor 1500 1>> /data/portmonitor.log 2>> /data/error.udp.log &
PIDDIR="/var/run/madcat"
PIDFILE="$PIDDIR/udp.pid"
echo $PIDDIR
echo $PIDFILE
if [ ! -d "$PIDDIR" ]; then
        mkdir $PIDDIR
fi
/opt/portmonitor/udp_ip_port_mon 192.168.22.150 /data/ sensor 1500 1>> /data/portmonitor.log 2>> /data/error.udp.log &
echo $! >$PIDFILE

