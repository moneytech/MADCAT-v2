# !/bin/bash
# Stand 2019-03-12
PIDDIR="/var/run/madcat"
TCPPID="$PIDDIR/tcp.pid"
TCPPOSTPID="$PIDDIR/tcppost.pid"
UDPPID="$PIDDIR/udp.pid"
ICMPPID="$PIDDIR/icmp.pid"
STATUS=""
CURRENT=""
STOP=0

sleep 3
while [ 1 ]; do
	sleep 2

	STATUS="$(date) [PID $$] List of not found pid-files, stoping if list not empty after colon:"
	echo TCP
	if [ -e "$TCPPID" ]; then
		CURRENT="TCP Monitor"
		kill -s 0 $(cat "$TCPPID") || /root/restart_portmonitor.sh $CURRENT 0<&- &>/dev/null &
		kill -s 0 $(cat "$TCPPID") || exit
	else
		STATUS=" $STATUS $TCPPID"
                STOP=1
	fi
	echo TCPPOST
	if [ -e "$TCPPOSTPID" ]; then
		CURRENT="TCP Postprocessor"
		kill -s 0 $(cat "$TCPPOSTPID") || /root/restart_portmonitor.sh $CURRENT 0<&- &>/dev/null &
		kill -s 0 $(cat "$TCPPOSTPID") || exit

	else
		STATUS=" $STATUS $TCPPOSTPID"
                STOP=1
	fi
	echo UDP
	if [ -e "$UDPPID" ]; then
		CURRENT="UDP Monitor"
		kill -s 0 $(cat "$UDPPID") ||  /root/restart_portmonitor.sh $CURRENT  0<&- &>/dev/null &
		kill -s 0 $(cat "$UDPPID") || exit
	else
		STATUS=" $STATUS $UDPPID"
                STOP=1
	fi
	echo ICMP
	if [ -e "$ICMPPID" ]; then
		CURRENT="ICMP Monitor"
		kill -s 0 $(cat "$ICMPPID") ||  /root/restart_portmonitor.sh $CURRENT  0<&- &>/dev/null &
		kill -s 0 $(cat "$ICMPPID") || exit
	else
		STATUS=" $STATUS $ICMPPID"
                STOP=1
	fi
	echo LOG
	echo "$STATUS" >/data/error.watchdog.log
	if [ $STOP == 1 ]; then
		echo STOP
		exit
	fi
done


