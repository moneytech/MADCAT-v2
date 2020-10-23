#!/usr/bin/python3
#coding=utf8
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
## MADCAT - Mass Attack Detecion Connection Acceptance Tool
 # Monitoring Module
 #
 #
 # Heiko Folkerts, BSI 2020
##

########################## IMPORTS ##########################
import sys, os, signal
import time
from datetime import datetime
import threading
import json
import psutil
import multiprocessing
import socket

########################## CONFIGURATION ##########################
## Only in this section changes are allowed (global configuration variables beginning with "DEF_"), thus for configuration purposes ;-)
# Timing
DEF_TIME_HEARTBEAT = 20
# System
DEF_CHECK_CPU = True
CPU_LOAD_ALERT = 80

DEF_CHECK_MEM = True
MEM_USED_ALERT = 80

DEF_CHECK_DISK = True
DISK_USED_ALERT = 80
DEF_DISK_LIST = ["/", "/home"]
#Reads the local database, thus configure a regular cron-job for "apt-get update"!
DEF_CHECK_UPDATES = True #Alerts, when security Updates are avaible
DEF_CHECK_LASTLOGIN = True #Alerts, when a login is active
# MADCAT
DEF_CHECK_LASTLOG = True #Alerst, when log has not been written since DEF_LOGTIME_ALERT seconds
DEF_LOGTIME_ALERT = 86400
DEF_LOG_LIST = ["/data/portmonitor.log",
                "/var/log/syslog"]

DEF_CHECK_MCVERSIONS = True #Does not alert, just informational
DEF_MCVERSION_LIST = ["/opt/portmonitor/tcp_ip_port_mon",
                    "/opt/portmonitor/udp_ip_port_mon",
                    "/opt/portmonitor/icmp_mon",
                    "/opt/portmonitor/raw_mon",
                    "/opt/portmonitor/tcp_ip_port_mon_postprocessor.py"]

# General
DEF_CHECK_PROCESSES = True #Alerts, when process is not running
DEF_PROCESS_LIST = ["sshd", 
                    "tcp_ip_port_mon", 
                    "udp_ip_port_mon", 
                    "icmp_mon"]

DEF_CHECK_NETWORKUSAGE = True #Alerts, when network usage exceeds the avarage of DEF_NETUSAGE_ALERT Bytes per second, measured in DEF_TIME_HEARTBEAT seconds
DEF_NETUSAGE_ALERT = 1000000
DEF_NETWORK_LIST = ["wlp8s0",
                    "enp9s0"]

DEF_CHECK_LISTNERS = True
#Whitelist of ports on which listners are allowed, empty to prevent alerts and set it to informational ("None")
DEF_WHITELISTED_PORTS = [22,
                         65535,
                         53]

########################## Version and Mascott strings ##########################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tools\n Monitoring Module\n v2.0 for MADCAT v2.0.x\nHeiko Folkerts, BSI 2020\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n hfo   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

########################## Locks for output ##########################
stderr_lock = threading.Lock()
stdout_lock = threading.Lock()

########################## Print on STDERR ##########################
def eprint(*args, **kwargs):
    stderr_lock.acquire()
    print(*args, file=sys.stderr, **kwargs)
    stderr_lock.release()
    return

########################## Signal Handler for gracefull shutdown ##########################
def signal_handler(signum, frame):
    #Evil,mean Hack to get a dictonary of signals
    SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) for n in dir(signal) if n.startswith('SIG') and '_' not in n )
    #Log time, PID and Signal
    logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
    eprint("\n" + logtime + " [PID " + str(os.getpid()) + "] Signal " + SIGNALS_TO_NAMES_DICT[signum] + " received. Shutting down. Bye!")
    sys.exit() #Terminate whole process including threads
    return

########################## Checks ##########################

from package_updates_check import *

alerts = dict()

def check_cpu():
    if not DEF_CHECK_CPU: return {"INFO" : "check disabled"}
    output = dict(zip(range(0,multiprocessing.cpu_count()), psutil.cpu_percent(interval=None, percpu=True)))
    sumload = 0.0
    for key, value in output.items():
            sumload += value
    avarage = sumload / multiprocessing.cpu_count()
    output['avarage'] = avarage
    if  avarage > CPU_LOAD_ALERT:
        alerts['cpuload'] = True
    else:
        alerts['cpuload'] = False
    return output

def check_mem():
    if not DEF_CHECK_MEM: return {"INFO" : "check disabled"}
    output = psutil.virtual_memory()._asdict()
    if  output['percent'] > MEM_USED_ALERT:
        alerts['memused'] = True
    else:
        alerts['memused'] = False
    return output

def check_disk():
    if not DEF_CHECK_DISK: return {"INFO" : "check disabled"}
    output = dict()
    alerts['diskused'] = False
    for disk in DEF_DISK_LIST:
        output[disk] = dict()
        output[disk]['status'] = dict(zip(["total", "used", "free"], psutil.disk_usage(disk)))
        used_percent = output[disk]['status']['used'] / output[disk]['status']['total'] * 100
        output[disk]['status']['used_percent'] = used_percent
        if  used_percent > DISK_USED_ALERT:
            alerts['diskused'] = True
    return output

def check_updates():
    if not DEF_CHECK_UPDATES: return {"INFO" : "check disabled"}
    output = print_result(get_update_packages())
    if  output['security updates']['avaible'] > 0:
        alerts['secupdates'] = True
    else:
        alerts['secupdates'] = False
    return output

def check_lastlogin():
    if not DEF_CHECK_LASTLOGIN: return {"INFO" : "check disabled"}
    output = dict()
    alerts['unknownentry'] = False
    lastlog = list(str(subprocess.check_output(['lastlog'])).split("\\n"))[1::] #Put output in list conaining rows and discard header
    for row in lastlog:
        collum = list(filter(None, row.split("  ")))
        #if "**Noch nie angemeldet**" in str(collum):
        #    continue
        #if "**Never logged in**" in str(collum):
        #    continue
        if len(collum) < 3: #Discard all never logged in users and trailing "'"
            continue
        if len(collum) == 3: #local login
            output[collum[0]] = dict()
            output[collum[0]]['port'] = collum[1].lstrip()
            output[collum[0]]['from'] = "local"
            output[collum[0]]['time'] = collum[2].lstrip()
            continue
        if len(collum) == 4: #remote login
            output[collum[0]] = dict()
            output[collum[0]]['port'] = collum[1].lstrip()
            output[collum[0]]['from'] = collum[2].lstrip()
            output[collum[0]]['time'] = collum[3].lstrip()
            continue
        output["UNRECOGNIZED ENTRY " + collum[0]] = str(collum)
        alerts['unknownentry'] = True
    who = list(str(subprocess.check_output(['who'])).split("\\n"))
    if  len(who) > 0:
        alerts['activelogin'] = True
    else:
        alerts['activelogin'] = False
    return output

def check_lastlog():
    if not DEF_CHECK_LASTLOG: return {"INFO" : "check disabled"}
    output = dict()
    alerts['lastlogtime'] = False
    for file in DEF_LOG_LIST:
        output[file] = dict()
        lastaccess = datetime.fromtimestamp(os.path.getmtime(file))
        output[file]['time'] = lastaccess.strftime("%Y-%m-%dT%H:%M:%S")
        if time.time() - time.mktime(lastaccess.timetuple()) > DEF_LOGTIME_ALERT:
            alerts['lastlogtime'] = True
    return output

def check_mcversions():
    if not DEF_CHECK_MCVERSIONS: return {"INFO" : "check disabled"}
    output = dict()
    for binary in DEF_MCVERSION_LIST:
        output[binary] = dict()
        try:
            version = list(str(subprocess.check_output([binary, 'version'])).split("\\n"))
            version = list(filter(lambda x: ' v' in x, version))
            output[binary]['version'] = str(version[0])
        except:
            output[binary]['version'] = "ERROR " + binary + " not found"
    return output

def check_processes():
    if not DEF_CHECK_PROCESSES: return {"INFO" : "check disabled"}
    output = dict()
    alerts['processdown'] = False
    #Iterate over the all the running process
    for processName in DEF_PROCESS_LIST:
        output[processName] = dict()
        output[processName]['running'] = False
        for proc in psutil.process_iter():
            try:
                if processName.lower() in proc.name().lower(): # Check if process name contains the given name string.
                    output[processName]['running'] = True
                    pidof = str(list(str(subprocess.check_output(["pidof",processName]).decode('ascii')).split("\n"))[0]).split()
                    pidof = dict(zip(range(0, len(pidof)), pidof))
                    for pid in pidof:
                        pidof[pid] = int(pidof[pid])
                    output[processName]['pid'] = pidof
                else:
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        if output[processName]['running'] == False:
            alerts['processdown'] = True
    return output

net_tx_prev = {}
net_rx_prev = {}
net_firstrun = True
def check_netusage():
    if not DEF_CHECK_NETWORKUSAGE: return {"INFO" : "check disabled"}
    output = dict()
    global net_tx_prev
    global net_rx_prev
    global net_firstrun
    net_tx_total = 0
    net_rx_total = 0
    alerts['netusage'] = False
    i = 0
    for nic in DEF_NETWORK_LIST:
        net_io = psutil.net_io_counters(pernic=True, nowrap=True)[nic]
        net_tx = net_io.bytes_sent
        net_rx = net_io.bytes_recv
        output[i] = dict()
        output[i]["nic"] = nic
        output[i]["tx_bytes"] = net_tx
        output[i]["rx_bytes"] = net_rx

        if net_firstrun: #First run?
            #initialiaze with actuall values
            net_tx_prev[nic] = net_tx
            net_rx_prev[nic] = net_rx

        output[i]["tx_bytes_sec"] = (net_tx - net_tx_prev[nic]) / DEF_TIME_HEARTBEAT
        output[i]["rx_bytes_sec"] = (net_rx - net_rx_prev[nic]) / DEF_TIME_HEARTBEAT
        net_tx_total += (net_tx - net_tx_prev[nic]) / DEF_TIME_HEARTBEAT
        net_rx_total += (net_rx - net_rx_prev[nic]) / DEF_TIME_HEARTBEAT
       
        if output[i]["tx_bytes_sec"] > DEF_NETUSAGE_ALERT:
            alerts['netusage'] = True
        if output[i]["rx_bytes_sec"] > DEF_NETUSAGE_ALERT:
            alerts['netusage'] = True

        #Save values
        net_tx_prev[nic] = net_tx
        net_rx_prev[nic] = net_rx
        i += 1
    output['tx_bytes_sec_total'] = net_tx_total
    output['rx_bytes_sec_total'] = net_rx_total
    net_firstrun = False
    return output

def check_listners():
    if not DEF_CHECK_LISTNERS: return {"INFO" : "check disabled"}
    output = dict()
    alerts['listner'] = False
    netstat = list(str(subprocess.check_output(['netstat', '-tulpne']).decode('ascii')).split("\n"))[2::]  #Put output in list conaining rows and discard header
    i = 0
    for row in netstat:
        collum = list(filter(None, row.split(" ")))
        if len(collum) >= 5 and ( "udp" in collum[0].lstrip() or "tcp" in collum[0].lstrip()): #udp or tcp listner
            output[i] = dict()
            output[i]['port'] = collum[0].lstrip()
            output[i]['recv-q'] = collum[1].lstrip()
            output[i]['send-q'] = collum[2].lstrip()
            output[i]['local address'] = collum[3].lstrip()
            output[i]['foreign address'] = collum[4].lstrip()
            if "tcp" in collum[0].lstrip(): #tcp state collum present
                output[i]['state'] = collum[5].lstrip()
                state = 1
            else: #no state collum present
                state = 0
            output[i]['user'] = collum[5+state].lstrip()
            output[i]['inode'] = collum[6+state].lstrip()
            output[i]['pid/program name'] = collum[7+state].lstrip()
            try: #optional: extra parameters
                output[i]['extra'] = collum[8+state].lstrip()
            except:
                pass

            if len(DEF_WHITELISTED_PORTS) > 0: #Is the ports whitelist enabled?
                if (not int(str(collum[3]).split(":")[-1]) in DEF_WHITELISTED_PORTS) and len(DEF_WHITELISTED_PORTS) > 0:
                    alerts['listner'] = True
                    output[i]['rogue'] = True
                else:
                    output[i]['rogue'] = False
            else:
                    alerts['listner'] = None
                    output[i]['rogue'] = None
            i += 1
            continue
        try:
            output["UNRECOGNIZED ENTRY " + collum[0]] = str(collum)
            alerts['uknownentry'] = True
        except: # ignore trailing empty entry
            continue
        i += 1
    return output


########################## Main ##########################
def main(argv):
    signal.signal(signal.SIGINT, signal_handler) #intialize Signal Handler for gracefull shutdown (SIGINT)
    stdout_lock.acquire()
    eprint(GLOBAL_MASCOTT) #print mascott
    eprint(GLOBAL_VERSION) #print version string
    eprint("================= Configuration [PID " + str(os.getpid()) + "]: =================")
    eprint("For alert configuration see head of " + argv[0])
    eprint("\nHeartbeat time in seconds: " + str(DEF_TIME_HEARTBEAT))
    eprint("Checks enabled (True/False): ")
    eprint("System:")
    eprint("\tCPU: \t\t\t\t" + str(DEF_CHECK_CPU))
    eprint("\tMemory: \t\t\t" + str(DEF_CHECK_MEM))
    eprint("\tDiskspace: \t\t\t" + str(DEF_CHECK_DISK))
    eprint("\t\tDisks to check: " + str(DEF_DISK_LIST))
    eprint("\tAvaible updates: \t\t" + str(DEF_CHECK_UPDATES) + "\n\t\tReads the local database, thus configure a regular cron-job for \"apt-get update\"!")
    eprint("\tLast logins: \t\t\t" + str(DEF_CHECK_LASTLOGIN))
    eprint("\tRunning processes: \t\t" + str(DEF_CHECK_PROCESSES))
    eprint("\t\tProcesses to check: " + str(DEF_PROCESS_LIST))
    eprint("\tNetwork usage: \t\t\t" + str(DEF_CHECK_NETWORKUSAGE))
    eprint("\t\tNetwork interface list: " + str(DEF_NETWORK_LIST))
    eprint("\tNetwork listners: \t\t" + str(DEF_CHECK_LISTNERS))
    eprint("\tLast time log(s) changed: \t" + str(DEF_CHECK_LASTLOG))
    eprint("\t\tLogs to check: " + str(DEF_LOG_LIST))
    eprint("MADCAT: " )
    eprint("\tMADCAT binaries version: \t" + str(DEF_CHECK_MCVERSIONS))
    eprint("\t\tMADCAT binary list: " + str(DEF_MCVERSION_LIST))
    eprint("\t\tMADCAT binary list: " + str(DEF_MCVERSION_LIST))
    eprint("==============================================================")
    logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
    eprint("\n" + logtime + " [PID " + str(os.getpid()) + "]" + " Starting up...")
    stdout_lock.release()

    global alerts

    while True:
        logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
        eprint(logtime + " [PID " + str(os.getpid()) + "]" + " Checking...")
        json_dict = {'time' : logtime, 'unixtime': time.time(), 'origin': 'MADCAT Monitoring', 'hostname': socket.gethostname()} #reset json output
        alerts = {} #reset alerts
        # CPU usage, memory, diskspace, avaible updates, last logins
        json_dict['cpu'] = check_cpu()
        json_dict['memory'] = check_mem()
        json_dict['diskspace'] = check_disk()
        json_dict['updates'] = check_updates()
        json_dict['lastlogin'] = check_lastlogin()
        # MADCAT-log last modified, versions
        json_dict['lastlog'] = check_lastlog()
        json_dict['madcat versions'] = check_mcversions()
        # Process running and PID(s), network usage
        json_dict['processes'] = check_processes()
        json_dict['network usage'] = check_netusage()
        json_dict['network listners'] = check_listners()
        # Alerts
        json_dict['alerts'] = alerts
        if True in alerts.values():
            json_dict['alerts']['alert_raised'] = True
        else:
            json_dict['alerts']['alert_raised'] = False
        
        stdout_lock.acquire()
        print(json.dumps(json_dict))
        stdout_lock.release()

        time.sleep(DEF_TIME_HEARTBEAT)

if __name__ == "__main__": #call "def main(argv)" as function with command line arguments
    main(sys.argv)