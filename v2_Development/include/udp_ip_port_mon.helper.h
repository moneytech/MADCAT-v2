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
 * UDP monitor library headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Heiko Folkerts, BSI 2018-2020
*/


#ifndef UDP_IP_PORT_MON_HELPER_H
#define UDP_IP_PORT_MON_HELPER_H

#include "udp_ip_port_mon.h"
#include "madcat.helper.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"

//Helper Functions:
void print_help_udp(char* progname); //print UDP help message
//Helper functions for proxy configuration:
int get_config_table(lua_State* L, char* name, struct proxy_conf_udp_t* pc); //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.
struct proxy_conf_udp_t* pcudp_init(); //initialize proxy configuration
void pcudp_push(struct proxy_conf_udp_t* pc, int listenport, char* backendaddr, int backendport); //push new proxy configuration item to linked list
struct proxy_conf_udp_node_t* pcudp_get_lport(struct proxy_conf_udp_t* pc, int listenport); //get proxy configuration for listenport
void pcudp_print(struct proxy_conf_udp_t* pc); //print proxy configuration
//udp connection structures and double linked list
struct udpcon_data_t* uc_init();
uint_least64_t uc_genid(char* src_ip, uint_least64_t src_port, char* dest_ip, uint_least64_t dest_port);
struct udpcon_data_node_t* uc_push(struct udpcon_data_t* uc, uint_least64_t id);
struct udpcon_data_node_t* uc_get(struct udpcon_data_t* uc, uint_least64_t id);
bool uc_del(struct udpcon_data_t* uc, uint_least64_t id);
void uc_print_list(struct udpcon_data_t* uc);

#endif
