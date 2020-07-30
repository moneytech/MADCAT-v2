#!/usr/bin/python
################################################################################
#This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
#
#    MADCAT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    MADCAT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
#
#    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
#
#    MADCAT ist Freie Software: Sie können es unter den Bedingungen
#    der GNU General Public License, wie von der Free Software Foundation,
#    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
#    veröffentlichten Version, weiter verteilen und/oder modifizieren.
#
#    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
#    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
#    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
#    Siehe die GNU General Public License für weitere Details.
#
#    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
#    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
################################################################################
## MADCAT - Mass Attack Detecion Connection Acceptance Tool
 # TCP Connection- and SYN-JSON data postprocessor for TCP/IP Portmonitor
 #
 #
 # Heiko Folkerts, BSI 2018-2019
##

from __future__ import print_function
import sys, os, signal
import time
import threading
import json

VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tool\n TCP Connection and SYN JSON-data postprocessor\n v1.0 for TCP/IP Portmonitor v1.0\nHeiko Folkerts, BSI 2018-2019\n"

#Time before a SYN is seen as part of a SYN-Scan, if connection can not be found in con_dict.
# Standard timeout is 63 seconds in Linux. For long connections 2*63=126sec. Seems more than reasonable.
# If a connection lasts longer, the SYN and the connection
#TODO: Discuss adding a general connection timeout to tcp_ip_port_mon.
########################## CONFIGURATION ##########################
## Only in this section (global variables beginning with "DEF_") changes are allowed for configuration purposes ;-)
DEF_CON_WAIT = 10 #Time to wait before a connection is processed to ensure that the matching SYN is present in sin_dict. Nothing to to with ICBMs.
DEF_SYN_TIMEOUT =  60 + DEF_CON_WAIT #Time after which a SYN not yet matched with a connection is interpreted as SYN-SCAN
DEF_HEADER_FIFO = "/tmp/header_json.tpm" #Named pipe with TCP-IP Header information, namely SYN
DEF_CONNECTION_FIFO = "/tmp/connect_json.tpm" #Named pipe with connection information

########################## Semaphore ##########################
GLOBAL_SHUTDOWN = False #Semaphore to indicate shutdown

########################## Global dictonarys and their locks ##########################
syn_dict = {} #Dictonary containing SYNs
syn_dict_lock = threading.Lock() #Lock for the SYN Dictonary
con_dict = {} #Dictonary containing connections (Dionaea stile)
con_dict_lock = threading.Lock() #Lock for the Cocnnecion Dictonary
# Trigger matching incoming connections with SYNs. SYN-Scans are handeled by a timout and therefore checked every second.
## So, event-driven action is only required for the Dictonary holding connections.
con_dict_evt = threading.Event()

########################## Locks for output ##########################
stderr_lock = threading.Lock()
stdout_lock = threading.Lock()

########################## SIGINT Signal Hander ##########################
# ...for gracefull shutdown
def signal_handler(signum, frame):
    global GLOBAL_SHUTDOWN, DEF_SYN_TIMEOUT
    logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]

    if not GLOBAL_SHUTDOWN: #prevent re-triggering
        GLOBAL_SHUTDOWN = True #Set semaphore, that shutdown is in progress
        eprint("\n" + logtime + " Shutdown in " + str(DEF_SYN_TIMEOUT) + "sec...")
        #Wait for the same time, a SYN would be accepted as a SYN-Scan, to catch all SYN-Scans in line and give the connections a last chance to catch up.
        time.sleep(DEF_SYN_TIMEOUT + 0.1)
        logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
        eprint(logtime + " [" + str(os.getpid()) + "]" + " ...bye!\n")
        sys.exit() #Terminate whole process including threads
    return

########################## Print on STDERR ##########################
def eprint(*args, **kwargs):
    stderr_lock.acquire()
    print(*args, file=sys.stderr, **kwargs)
    stderr_lock.release()
    return

########################## Fill SYN dictonary with data from corresponding FiFo ##########################
def build_syn_dict(fifo_file):
    global syn_dict, syn_dict_lock, GLOBAL_SHUTDOWN

    hdrfifo = open(fifo_file,"r") #Open SYN-FiFo
    while True: #Reading Loop
        #eprint("build_syn_dict")
        hdrjson = hdrfifo.readline() #Read JSON output from FiFo. Blocking!
        if GLOBAL_SHUTDOWN: #To prevent falls "not found"s: During Shutdown no (new) SYNs are acquired, but connections.
            continue
        syn_dict_lock.acquire() #Acquire lock on SYN dict
        try:
            hdrobj = json.loads(hdrjson) #unmarshal JSON from FiFo
        except ValueError:
            logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
            eprint(logtime + " [" + str(os.getpid()) + "]" + " Error: " + DEF_HEADER_FIFO + " closed?") 
            if not GLOBAL_SHUTDOWN: #prevent re-triggering
                os.kill(os.getpid(), signal.SIGINT)
            return
        #Build ID (aka tag) from source address, destination port and source port
        synid = str(hdrobj.get("ip").get("src_addr")) + "_" + \
                str(hdrobj.get("tcp").get("dest_port")) + "_" + str(hdrobj.get("tcp").get("src_port"))
        syn_dict.update({synid : hdrobj}) #append SYN to dictonary

        syn_dict_lock.release() #release lock
        #eprint("SYN:") #DEBUG
        #eprint(syn_dict) #DEBUG
        #eprint("") #DEBUG
    return

########################## Fill Connection dictonary with data from corresponding FiFo ##########################
def build_con_dict(fifo_file):
    global con_dict, con_dict_lock

    confifo = open(fifo_file,"r") #open Connection-FiFo
    while True: #Reading loop
        #eprint("build_con_dict")
        conjson = confifo.readline() #Read JSON output from FiFo. Blocking!
        con_dict_lock.acquire() #Aquire lock on Connection dictonary

        try:
            conobj = json.loads(conjson) #unmarshal JSON from FiFo
        except ValueError:
            logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
            eprint(logtime + " [" + str(os.getpid()) + "]" + " Error: " + DEF_CONNECTION_FIFO + " closed?") 
            if not GLOBAL_SHUTDOWN: #prevent re-triggering
                os.kill(os.getpid(), signal.SIGINT)
            return
        #Build ID (aka tag) from source address, destination port and source port
        conid = str(conobj.get("src_ip")) + "_" + str(conobj.get("dest_port")) + "_" + str(conobj.get("src_port"))
        con_dict.update({conid : conobj}) #append Connection to dictonary

        con_dict_lock.release() #release lock
        con_dict_evt.set() #indicate new entry in dictonary
        #eprint("CON:") #DEBUG
        #eprint(con_dict) #DEBUG
        #eprint("") #DEBUG
    return

########################## Print connections including their SYNs (if feasable) to STDOUT ##########################
def output_accepted_con():
    global con_dict, con_dict_lock, syn_dict, syn_dict_lock
    global DEF_CON_WAIT, GLOBAL_SHUTDOWN
    #eprint("CON_O:") #DEBUG
    #eprint(time.time()) #DEBUG
    while True:
        con_dict_evt.wait(); #Wait for new entry in con_dict
        con_dict_evt.clear() #Indicate event has been seen
        time.sleep(DEF_CON_WAIT) #wait for SYN to catch up, because pcap_next() is slower than accept()
        while len(con_dict) > 0: #Repeat till every connection has been processed
            con_dict_lock.acquire() # Aquire Locks for Connection and...
            syn_dict_lock.acquire() # Lock SYN dictonary
            con_dict_keys = con_dict.keys() #Snapshot keys
            syn_dict_keys = syn_dict.keys() #Snapshot keys
            #eprint("output_accept_con") #DEBUG
            for conid in con_dict_keys: #Iterate over connections
                found = False #Set boolean, that a match between SYN and Connection has been found to false in the beginning
                #eprint(con_dict.get(conid).get("unixtime") + DEF_CON_WAIT < time.time())  #DEBUG
                #eprint(syn_dict_keys) #DEBUG
                for synid in syn_dict_keys: #Iterate over SYNs and...
                #for synid in syn_dict: #Debug: Provoke "RuntimeError: dictionary changed size during iteration" for error handling test
                    if conid == synid and not found: #...search for matching tag (aka. id)
                        #eprint("output_accepted_con FOUND " + conid) #DEBUG
                        #complete JSON output
                        found = True #if a match has been made, set found to true
                        #Combine connection information and Information from SYN (e.g. TCP/IP Headers) to one JSON Object. Set connection.type to "accept",
                        # to indicate, that a complete connection (full 3-Way Handshake) has been made and a TCP-Stream might have been recorded
                        output = {} #begin new JSON output
                        output.update({"origin": "MADCAT", 
                                       "timestamp": con_dict.get(conid).get("timestamp"),
                                       "src_ip": con_dict.get(conid).get("src_ip"),
                                       "src_port": con_dict.get(conid).get("src_port"),
                                       "dest_ip": con_dict.get(conid).get("dest_ip"),
                                       "dest_port": con_dict.get(conid).get("dest_port"),
                                       "proto": con_dict.get(conid).get("proto"),
                                       "event_type": con_dict.get(conid).get("event_type"),
                                       "unixtime" : con_dict.get(conid).get("unixtime"),
                                       "flow" : con_dict.get(conid).get("flow"),
                                       "ip" :  syn_dict.get(synid).get("ip"),
                                       "tcp" :  syn_dict.get(synid).get("tcp"),
                                       })
                        stdout_lock.acquire()
                        print(json.dumps(output) + "\n") #Marshal JSON and print to STDOUT
                        sys.stdout.flush()
                        stdout_lock.release()
                        del con_dict[conid] #Delete Matched connection and ...
                        del syn_dict[synid] #...SYN from dictonarys
                        continue #Go to next entry in SYN dictonary to...
                    if conid == synid and found: #...find (theoreticaly more or less)) possible duplicates and...
                        #eprint("DUPLICATE SYN " + conid) #DEBUG
                        del syn_dict[synid] #...delete them, so no falls "SYN-scans" are beeing reported
                #Print Connection without matching SYN. If they appear, it might be a problem with timouts and timing.
                # These connections might be identified by the "header" : "syn_not_found" tag.
                # A corresponding "connection.type" : "syn_scan" (really) SHOULD exist.
                if not found and not GLOBAL_SHUTDOWN: #To prevent falls "not found"s: During Shutdown no (new) SYNs are acquired, but connections.
                    #Wait a minimum of DEF_CON_WAIT + DEF_SYN_TIMOUT before processing connection w/o SYN to ensure SYN is really not present.
                    if con_dict.get(conid).get("unixtime") + DEF_CON_WAIT + DEF_SYN_TIMEOUT < time.time():
                        #"incomplete" JSON output
                        #eprint("NOT Found " + conid)  #DEBUG
                        output = {} # Begin new JSON output
                        #Compose JSON object, containing only the connection data and the "no_syn" tag event_type
                        output.update({"origin": "MADCAT", 
                                       "timestamp": con_dict.get(conid).get("timestamp"),
                                       "src_ip": con_dict.get(conid).get("src_ip"),
                                       "src_port": con_dict.get(conid).get("src_port"),
                                       "dest_ip": con_dict.get(conid).get("dest_ip"),
                                       "dest_port": con_dict.get(conid).get("dest_port"),
                                       "proto": con_dict.get(conid).get("proto"),
                                       "event_type": "no_syn",
                                       "unixtime" : con_dict.get(conid).get("unixtime"),
                                       "flow" : con_dict.get(conid).get("flow"),
                                       })
                        stdout_lock.acquire()
                        print(json.dumps(output) + "\n") #Marshal JSON and print to STDOUT
                        sys.stdout.flush()
                        stdout_lock.release()
                        del con_dict[conid] #Delete Un-Matched connection
            con_dict_lock.release() #Release locks
            syn_dict_lock.release()
            time.sleep(1) #sleep one second before next repetition
    return

########################## Print SYNs as SYN-Scans after configured timeout as JSON on STDOUT ##########################
def output_syn_scans(syn_timeout):
    global syn_dict, syn_dict_lock

    while True: #Loop checking for SYNs without connection after syn_timout
        #eprint("output_syn_scans")
        syn_dict_lock.acquire() #Aquire lock on SYN dictonary
        for synid in syn_dict.keys(): #Iterate over items in SYN dictonary
            if syn_dict.get(synid).get("unixtime") + syn_timeout < time.time(): #Check if specific SYN exceeded timeout
                output = {} #Begin new JSON output
                #Build Dionaea-like (pseudo-)Header from IP- and TCP-Header Information and append IP- and TCP-Header information
                output.update({"origin": "MADCAT", 
                               "timestamp": syn_dict.get(synid).get("timestamp"),
                               "src_ip": syn_dict.get(synid).get("ip").get("src_addr"),
                               "src_port": syn_dict.get(synid).get("tcp").get("src_port"),
                               "dest_ip": syn_dict.get(synid).get("ip").get("dest_addr"),
                               "dest_port":syn_dict.get(synid).get("tcp").get("dest_port"),
                               "proto": "TCP",
                               "event_type": "syn_scan",
                               "unixtime" : syn_dict.get(synid).get("unixtime"),
                               "ip" :  syn_dict.get(synid).get("ip"),
                               "tcp" :  syn_dict.get(synid).get("tcp"),
                               })
                stdout_lock.acquire()
                print(json.dumps(output) + "\n") #Marshal JSON and print to STDOUT
                sys.stdout.flush()
                stdout_lock.release()
                del syn_dict[synid] #Delete outdated SYN from dictonary
    
        syn_dict_lock.release() #release lock
        time.sleep(1) #Iterate every second to recognize timed out SYNs
        # Best place for consecutive debugging output:
        """
        eprint("syn_dict:") # DEDBUG
        eprint(syn_dict) # DEDBUG
        eprint("con_dict:") # DEDBUG
        eprint(con_dict) # DEDBUG
        """
    return

########################## Configure Threads ##########################
##All threads are deamonized to make them exit with the parent process
#Threads for data acquisition
syn_dict_th = threading.Thread(target = build_syn_dict, args = [DEF_HEADER_FIFO]) #Argument: Path to the named pipe containing header information
syn_dict_th.setDaemon(True)
con_dict_th = threading.Thread(target = build_con_dict, args = [DEF_CONNECTION_FIFO]) #Argument: Path to the named pipe containing connection information
con_dict_th.setDaemon(True)
#Threads for generating JSON and cleaning up dictonarys
output_syn_scans_th = threading.Thread(target = output_syn_scans, args = [DEF_SYN_TIMEOUT]) #Argument: Time after which a SYN is considered a scan
output_syn_scans_th.setDaemon(True)
output_accepted_con_th = threading.Thread(target = output_accepted_con)
output_accepted_con_th.setDaemon(True)

########################## Main ##########################
def main(argv):
    global GLOBAL_SHUTDOWN
    logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]

    eprint(VERSION) #print version string
    eprint("================= Configuration [" + str(os.getpid()) + "] : =================")
    eprint("Time after which a SYN not yet matched with a connection is interpreted as SYN-SCAN:\n %.1fsec " % DEF_SYN_TIMEOUT )
    eprint("Time to wait before a connection is processed to ensure that the matching SYN is present:\n %.1fsec" % DEF_CON_WAIT)
    eprint("Named pipe with TCP/IP Header information, namely SYN:\n " + DEF_HEADER_FIFO)
    eprint("Named pipe with connection information:\n " + DEF_CONNECTION_FIFO)
    eprint("==================================================")
    eprint("\n" + logtime + " [" + str(os.getpid()) + "]" + " Starting up...")

    signal.signal(signal.SIGINT, signal_handler) #intialize Signal Handler for gracefull shutdown (SIGINT)

    #Start threads for data acquisition
    syn_dict_th.start() 
    con_dict_th.start()
    #Start threads for generating output and cleaning up dictonarys
    output_accepted_con_th.start()
    output_syn_scans_th.start()

    logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
    eprint(logtime + " [" + str(os.getpid()) + "]" + " ...running.")
    #Sleep and wait for "death by signal" (unfortunetly their is no signal "CHOCOLATE")... 
    while True:
        #Check Threads every second. If one died try a graceful shutdown
        time.sleep(1)
        logtime = time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime(time.time())) + str(time.time()-int(time.time()))[1:8]
        if not syn_dict_th.isAlive():
            eprint(logtime + " [" + str(os.getpid()) + "]" + " Thread build_syn_dict died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if not con_dict_th.isAlive():
            eprint(logtime + " [" + str(os.getpid()) + "]" + " Thread build_con_dict died, shutting down...")          
            os.kill(os.getpid(), signal.SIGINT)
        if not output_accepted_con_th.isAlive():
            eprint(logtime + " [" + str(os.getpid()) + "]" + " Thread output_accepted_con died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if not output_syn_scans_th.isAlive():
            eprint(logtime + " [" + str(os.getpid()) + "]" + " Thread output_syn_scans died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
    return

if __name__ == "__main__": #call "def main(argv) as function with command line arguments
    main(sys.argv)

