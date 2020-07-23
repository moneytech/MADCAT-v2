# !/bin/bash
# Stand 2019-02-25
#/opt/portmonitor/tcp_port_mon 192.168.22.150 65535 5 /data/ 1>> /data/portmonitor.log 2>> /data/error.tcp.log &
PIDDIR="/var/run/madcat"
PIDFILE="$PIDDIR/tcp.pid"
echo $PIDDIR
echo $PIDFILE
if [ ! -d "$PIDDIR" ]; then
	mkdir $PIDDIR
fi
/opt/portmonitor/tcp_ip_port_mon enx0008bbfd8a82 192.168.22.150 65535 5 sensor /data/ 2>> /data/error.tcp.log 1>>/dev/null &
echo $! >$PIDFILE


