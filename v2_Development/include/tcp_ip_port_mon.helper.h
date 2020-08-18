/*******************************************************************************
This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
    MADCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    MADCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.

    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
    MADCAT ist Freie Software: Sie können es unter den Bedingungen
    der GNU General Public License, wie von der Free Software Foundation,
    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License für weitere Details.
    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
*******************************************************************************/
/* MADCAT - Mass Attack Detecion Connection Acceptance Tool
 * TCP monitor library headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Heiko Folkerts, BSI 2018-2020
*/


#ifndef TCP_IP_PORT_MON_HELPER_H
#define TCP_IP_PORT_MON_HELPER_H

#include "tcp_ip_port_mon.common.h"
#include "madcat.helper.h"

//Capture only TCP-SYN's, for some sytems (Linux Kernel >= 5 ???) own host IP has to be appended,
//so that the final filter string looks like "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 & dst host 1.2.3.4"
#define PCAP_FILTER "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 and dst host "
#define HEADER_FIFO "/tmp/header_json.tpm"
#define CONNECT_FIFO "/tmp/connect_json.tpm"

#define PCN_STRLEN 6 //listen- and backport string length in proxy_conf_tcp_node_t
#define STR_BUFFER_SIZE 65536 //Generic string buffer size

struct proxy_conf_tcp_node_t //linked list element to hold proxy configuration items
{
    struct proxy_conf_tcp_node_t* next;

    int listenport;
    char listenport_str[PCN_STRLEN];
    int backendport;
    char backendport_str[PCN_STRLEN];
    char* backendaddr;

    pid_t pid; //Process ID of corresponding proxy.
};

struct proxy_conf_tcp_t { //proxy configuration
    struct proxy_conf_tcp_node_t* portlist; //head pointer to linked list with proxy configuration items
    bool portmap[65536]; //map of ports used to proxy network traffic
    int num_elemnts;
} *pc; //globally defined to be easly accesible by functions

struct json_data_t { //json_data structure...
    struct json_data_node_t *list;
} *jd; //..defined globally as "jd" for easy access in all functions

struct json_data_node_t { //json data list element
    struct json_data_node_t *next; //next element in list
    struct json_data_node_t *prev; //prev element in list
    long long unsigned int id; //id, usally originating from a pointer (void*) to e.g. an epoll handler structure
    
    //all variables of json output, exepct constant string values e.g. "proxy_flow" or "closed"
    char* src_ip;
    int   src_port;
    char* dest_ip;
    char* dest_port;
    char* timestamp;
    char* unixtime;
    char* start;
    char* end;
    long long unsigned int bytes_toserver;
    long long unsigned int bytes_toclient;    
    char* proxy_ip;
    int   proxy_port;
    char* backend_ip;
    char* backend_port;
    
};

//Helper Functions:
void print_help_tcp(char* progname); //print TCP help message
int init_pcap(char* dev, char* dev_addr, pcap_t **handle);
void drop_root_privs(struct user_t user, const char* entity);
//Signal Handler:
void sig_handler_parent(int signo); //Signal Handler for parent watchdog
void sig_handler_sigchld(int signo); //Signal Handler for Listner Parent to prevent childs becoming Zombies
void sig_handler_child(int signo); //Signal Handler for childs
void sig_handler_shutdown(int signo); //Signal Handler for SIGUSR1 to initiate gracefull shutdown, e.g. by CHECK-Macro
//Helper functions for proxy configuration:
int get_config_table(lua_State* L, char* name, struct proxy_conf_tcp_t* pc); //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.
struct proxy_conf_tcp_t* pctcp_init(); //initialize proxy configuration
void pctcp_push(struct proxy_conf_tcp_t* pc, int listenport, char* backendaddr, int backendport); //push new proxy configuration item to linked list
struct proxy_conf_tcp_node_t* pctcp_get_lport(struct proxy_conf_tcp_t* pc, int listenport); //get proxy configuration for listenport
struct proxy_conf_tcp_node_t* pctcp_get_pid(struct proxy_conf_tcp_t* pc, pid_t pid); //get proxy configuration for proxy with Process ID "pid"
void pctcp_print(struct proxy_conf_tcp_t* pc); //print proxy configuration
//Helper functions for json data structure and double linked list //TODO: Make list thread-safe?
struct json_data_t* jd_init();  //initialize json data structure
void jd_push(struct json_data_t* jd, long long unsigned int id); //push new json data list node wit id "id" to list
struct json_data_node_t* jd_get(struct json_data_t* jd, long long int id); //get json data node by id
bool jd_del(struct json_data_t* jd, long long int id);  //remove json data node by id
void jd_print_list(struct json_data_t* jd); //print complete json data list

#endif
