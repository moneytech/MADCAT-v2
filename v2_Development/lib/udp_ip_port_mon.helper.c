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
/* MADCAT -Mass Attack Detecion Connection Acceptance Tool
 * UDP port monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Heiko Folkerts, BSI 2018-2020
*/

//Helper Functions
#include "madcat.helper.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"
#include "udp_ip_port_mon.helper.h"

void print_help_udp(char* progname) //print help message
{
    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \thostaddress = \"127.1.1.1\"\n\
            \tuser = \"hf\"\n\
            \tpath_to_save_udp_data = \"./upm/\" --Must end with trailing \"/\", will be handled as prefix otherwise\n\
            \t--bufsize = \"1024\" --optional\n\
        ", progname);

    fprintf(stderr, "\nLEGACY SYNTAX (pre v1.1.5)t: %s hostaddress path_to_save_udp-data user [buffer_size]\n\tBuffer Size defaults to %d Bytes.\n \
\tPath to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\n \
Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.\n \
\tiptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP\n\n \
\tMust be run as root, but the priviliges will be droped to user after the socket has been opened.\n", progname, DEFAULT_BUFSIZE);
    
    return;
}

//Helper functions for proxy configuration

int get_config_table(lua_State* L, char* name, struct proxy_conf_udp_t* pc) //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.
{
    char* backendaddr = 0;
    int backendport = 0;

    int num_elements = 0;
    
    lua_getglobal(L, name); //push objekt "name" to stack and...

    if ( !lua_istable(L, -1) ) //...check if this objekt is a table
    {
        fprintf(stderr, "\tNo proxy config found. Variable \"%s\" must be a LUA table.\n", name);
        return num_elements;
    }
    
    //Iterate over all possible portnumbers.
    //TODO: Think about a more clever solution.
    for (int listenport = 0; listenport<65536; listenport++)
    {
        //fprintf(stderr,"LOOP %d:", listenport);
        //pcudp_print(pc);
                
        lua_pushnumber(L, listenport); //push actuall portnumber on stack and...
        lua_gettable(L, -2);  //...call lua_gettable with this portnumber as key
        if( !lua_isnil(L,-1) ) //if corresponding value is not NIL...
        {
            lua_pushnumber(L, 1); //push "1" on the stack for the first elemnt in sub-table and...
            lua_gettable(L, -2);  //...fetch this entry
            backendaddr = (char*) lua_tostring(L, -1);
            lua_pop(L, 1); //remove result from stack
            
            lua_pushnumber(L, 2); //push "2" on the stack for the second elemnt in sub-table and...
            lua_gettable(L, -2); //...fetch this entry
            backendport = lua_tonumber(L, -1);
            lua_pop(L, 1);  //remove result from stack      
            
            pcudp_push(pc, listenport, backendaddr, backendport);
            pc->portmap[listenport] = true;
            num_elements++;
        }
        lua_pop(L, 1); //remove sub-table from stack
    }
    return num_elements;
}

struct proxy_conf_udp_t* pcudp_init() //initialize proxy configuration
{
    struct proxy_conf_udp_t* pc = malloc (sizeof(struct proxy_conf_udp_t)); 
    pc->portlist = 0; //set headpointer to 0
    for (int listenport = 0; listenport<65536; listenport++) pc->portmap[listenport] = false; //initilze map of ports used to proxy network traffic
    return pc;
}

void pcudp_push(struct proxy_conf_udp_t* pc, int listenport, char* backendaddr, int backendport) //push new proxy configuration item to linked list
{
    struct proxy_conf_udp_node_t* pcudp_node = malloc (sizeof(struct proxy_conf_udp_node_t));
    
    pcudp_node->listenport = listenport;
     snprintf(pcudp_node->listenport_str, PCN_STRLEN, "%d", listenport);
    //pcudp_node->backendaddr = backendaddr; //Make copy instead, to get full control over data and circumvent data corruption by free(backendaddr), etc.
    pcudp_node->backendaddr = malloc(strlen(backendaddr)+1);
     strncpy(pcudp_node->backendaddr, backendaddr, strlen(backendaddr)+1);
    pcudp_node->backendport = backendport;
     snprintf(pcudp_node->backendport_str, PCN_STRLEN, "%d", backendport);

    pcudp_node->next = pc->portlist;
    pc->portlist = pcudp_node;
    pc->num_elemnts++;
    return;
}

struct proxy_conf_udp_node_t* pcudp_get_lport(struct proxy_conf_udp_t* pc, int listenport) //get proxy configuration for listenport
{
    struct proxy_conf_udp_node_t* result = pc->portlist;
    while ( result != 0)
    {
        if(result->listenport == listenport) return result;
        result = result->next;
    }
    return 0;
}

void pcudp_print(struct proxy_conf_udp_t* pc) //print proxy configuration
{
    struct proxy_conf_udp_node_t* pcudp_node = pc->portlist;
    while ( pcudp_node != 0)
    {
        fprintf(stderr, "\tProxy local port: %d -> Backend socket: %s:%d\n", pcudp_node->listenport, pcudp_node->backendaddr, pcudp_node->backendport);
        pcudp_node = pcudp_node->next;
    }
    return;
}

//udp connection structures and double linked list

struct udpcon_data_t* uc_init()
{
    struct udpcon_data_t* uc = malloc (sizeof(struct udpcon_data_t));
    uc->list = 0;
    return uc;
}

uint_least64_t uc_genid(char* src_ip, uint64_t src_port, char* dest_ip, uint64_t dest_port)
{
    uint_least64_t id = 0;
    struct sockaddr_in src_sa;
    struct sockaddr_in dest_sa;
    char str[INET_ADDRSTRLEN];
    // store this IP addresses in sa:
    inet_pton(AF_INET, src_ip, &(src_sa.sin_addr));
    inet_pton(AF_INET, dest_ip, &(dest_sa.sin_addr));
    id = ((uint_least64_t) src_sa.sin_addr.s_addr << 16 | src_port)  ^ ((uint_least64_t) dest_sa.sin_addr.s_addr << 16 | dest_port);
    return id;
}

struct udpcon_data_node_t* uc_push(struct udpcon_data_t* uc, uint_least64_t id)
{
    struct udpcon_data_node_t* uc_node = malloc (sizeof(struct udpcon_data_node_t));

    uc_node->id_fromclient = id;
    uc_node->id_tobackend = 0;

    
    uc_node->backend_socket = 0;
    uc_node->backend_socket_fd = 0;
    uc_node->client_socket = 0;
    uc_node->client_socket_fd = 0;

    uc_node->last_seen = 0;

    uc_node->src_ip =  EMPTY_STR;
    uc_node->src_port = 0;
    uc_node->dest_ip =  EMPTY_STR;
    uc_node->dest_port =  0;
    uc_node->timestamp =  EMPTY_STR;
    uc_node->unixtime =  0;
    uc_node->start =  EMPTY_STR;
    uc_node->end =  EMPTY_STR;
    uc_node->bytes_toserver =  0;
    uc_node->bytes_toclient =  0;
    uc_node->proxy_ip =  EMPTY_STR;
    uc_node->proxy_port =  0;
    uc_node->backend_ip =  EMPTY_STR;
    uc_node->backend_port =  0;

    if(uc->list != 0) uc->list->prev=uc_node;
    uc_node->next = uc->list;
    uc->list = uc_node;
    uc_node->prev = 0;

    return uc_node;
}

struct udpcon_data_node_t* uc_get(struct udpcon_data_t* uc, uint_least64_t id)
{
    struct udpcon_data_node_t* result = uc->list;
    while ( result != 0)
    {
        if(result->id_fromclient == id || result->id_tobackend == id) return result;
        result = result->next;
    }
    return 0;
}

bool uc_del(struct udpcon_data_t* uc, uint_least64_t id)
{
    struct udpcon_data_node_t* uc_node = uc_get(uc, id);
    if (uc_node == 0) return false;

    if (uc_node->backend_socket != 0) free(uc_node->backend_socket);
    if (uc_node->client_socket != 0) free(uc_node->client_socket);
    if (uc_node->src_ip != EMPTY_STR) free(uc_node->src_ip);
    if (uc_node->dest_ip !=  EMPTY_STR) free(uc_node->dest_ip);
    if (uc_node->timestamp !=  EMPTY_STR) free(uc_node->timestamp);
    if (uc_node->start !=  EMPTY_STR) free(uc_node->start);
    if (uc_node->end !=  EMPTY_STR) free(uc_node->end);
    if (uc_node->proxy_ip !=  EMPTY_STR) free(uc_node->proxy_ip);
    if (uc_node->backend_ip !=  EMPTY_STR) free(uc_node->backend_ip);

    if (uc_node == uc->list) uc->list = uc_node->next;
    if (uc_node->prev != 0) uc_node->prev->next = uc_node->next;
    if (uc_node->next != 0) uc_node->next->prev = uc_node->prev;

    free(uc_node);

    return true;
}

void uc_print_list(struct udpcon_data_t* uc)
{
    struct udpcon_data_node_t* uc_node = uc->list;

    fprintf(stderr, "\n<START>\n");

    while ( uc_node != 0 )
    {
        fprintf(stderr, "\n\
uint_least64_t id int id_fromclient: %p\n\
uint_least64_t id int id_tobackend: %p\n\
void* uc_node: %p\n\
struct udpcon_data_node_t *next: %p\n\
struct udpcon_data_node_t *prev: %p\n\
long long int last_seen: %llu\n\
char* src_ip: %s\n\
int   src_port: %d\n\
char* dest_ip: %s\n\
char* dest_port: %d\n\
char* timestamp: %s\n\
char* unixtime: %llu\n\
char* start: %s\n\
char* end: %s\n\
long long unsigned int bytes_toserver: %lld\n\
long long unsigned int bytes_toclient: %lld\n\
char* proxy_ip: %s\n\
int   proxy_port: %d\n\
char* backend_ip: %s\n\
char* backend_port: %d\n\
\n",\
(void*) uc_node->id_fromclient,\
(void*) uc_node->id_tobackend,\
uc_node,
uc_node->next,\
uc_node->prev,\
uc_node->last_seen,\
uc_node->src_ip,\
uc_node->src_port,\
uc_node->dest_ip,\
uc_node->dest_port,\
uc_node->timestamp,\
uc_node->unixtime,\
uc_node->start,\
uc_node->end,\
uc_node->bytes_toserver,\
uc_node->bytes_toclient,\
uc_node->proxy_ip,\
uc_node->proxy_port,\
uc_node->backend_ip,\
uc_node->backend_port\
);

        uc_node = uc_node->next;
    }

    fprintf(stderr, "<END>\n\n");
    return;
}