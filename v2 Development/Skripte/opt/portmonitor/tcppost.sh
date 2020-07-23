# !/bin/bash
# Stand 2019-02-25
PIDDIR="/var/run/madcat"
PIDFILE="$PIDDIR/tcppost.pid"
echo $PIDDIR
echo $PIDFILE
if [ ! -d "$PIDDIR" ]; then
        mkdir $PIDDIR
fi
/opt/portmonitor/tcp_ip_port_mon_postprocessor.py >>/data/portmonitor.log 2>>/data/error.tcppost.log &
echo $! >$PIDFILE

