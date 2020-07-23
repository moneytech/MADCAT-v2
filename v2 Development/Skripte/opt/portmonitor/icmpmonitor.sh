# !/bin/bash
# Stand 2019-02-25
PIDDIR="/var/run/madcat"
PIDFILE="$PIDDIR/icmp.pid"
echo $PIDDIR
echo $PIDFILE
if [ ! -d "$PIDDIR" ]; then
        mkdir $PIDDIR
fi
/opt/portmonitor/icmp_mon 192.168.22.150 /data/ hf 2>> /data/error.icmp.log 1>>/data/portmonitor.log &
echo $! >$PIDFILE

