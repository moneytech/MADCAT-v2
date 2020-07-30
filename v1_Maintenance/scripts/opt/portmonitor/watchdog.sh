# !/bin/bash
# Stand 2019-03-12
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


