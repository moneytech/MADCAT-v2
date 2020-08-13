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
 * TCP-IP port monitor.
 *
 *
 * Heiko Folkerts, BSI 2018-2020
*/

#include "tcp_ip_port_mon.helper.h"

//Helper functions

#include "madcat.helper.h"

void print_help_tcp(char* progname) //print help message
{
    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \tinterface = \"enp0s8\"\n\
            \thostaddress = \"10.1.2.3\"\n\
            \tlistening_port = \"65535\"\n\
            \tconnection_timeout = \"10\"\n\
            \tuser = \"hf\"\n\
            \tpath_to_save_tcp_streams = \"./tpm/\" --Must end with trailing \"/\", will be handled as prefix otherwise\n\
            \t--max_file_size = \"1024\" --optional\n\
            \t--TCP Proxy configuration\n\
            \ttcpproxy = {\n\
            \t-- [<listen port>] = { \"<backend IP>\", <backend Port> },\n\
            \t\t[22]  = { \"192.168.10.222\", 22 },\n\
            \t\t[80]  = { \"192.168.20.80\", 8080 },\n\
            \t}\n\
        ", progname);

    fprintf(stderr, "\nLEGACY SYNTAX (pre v1.1.5):\n    %s interface hostaddress listening_port connection_timeout user path_to_save_tcp-streams [max_file_size]\n\
        Path to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\
        The last paramteter, max_file_size, is the maximum size of saved streams,\n\
        but the last TCP Datagramm exceeding this size will be saved anyway.\n", progname);

    fprintf(stderr,"\nExample Netfilter Rule to work properly:\n\
        iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 10.1.2.3:65535\n\
        Listening Port is 65535 and hostaddress is 10.1.2.3 in this example.\n\n\
    Must be run as root, but the priviliges will be droped to \"user\".\n\n\
    Opens two named pipes (FiFo) containing live JSON output:\n\
        \"%s\" for stream connection data, \"%s\" for header data.\n", CONNECT_FIFO, HEADER_FIFO);
    return;
}

int init_pcap(char* dev, char* dev_addr, pcap_t **handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];// Error string 
    struct bpf_program fp;    // The compiled filter 
    char filter_exp[ strlen(PCAP_FILTER) + strlen(dev_addr) + 1 ]; //The filter expression
    bpf_u_int32 mask;    // Our netmask 
    bpf_u_int32 net;    // Our IP 

    //Capture only TCP-SYN's...
    strncpy(filter_exp, PCAP_FILTER, sizeof(filter_exp));
    //...for some systems (Linux Kernel >= 5 ???) own host IP has to be appended, so that the final filter string looks like "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 & dst host 1.2.3.4"
    strncat(filter_exp, dev_addr, sizeof(filter_exp) - sizeof(PCAP_FILTER));

    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] PCAP Filter Expression: \"%s\"\n", getpid(), filter_exp);
        fflush(stderr);
    #endif

    // Find the properties for the device 
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        return -1;
    // Open the session in non-promiscuous mode 
    *handle = pcap_open_live(dev, BUFSIZ, 0, 100, errbuf);
    if (handle == NULL)
        return -2;
    // Compile and apply the filter 
    if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1)
        return -3;
    if (pcap_setfilter(*handle, &fp) == -1)
        return -4;

    return 0;
}

void drop_root_privs(struct user_t user, const char* entity) // if process is running as root, drop privileges
{
    if (getuid() == 0) {
        fprintf(stderr, "%s droping priviliges to user %s...", entity, user.name);
        get_user_ids(&user); //Get traget user UDI + GID
        CHECK(setgid(user.gid), == 0); // Drop GID first for security reasons!
        CHECK(setuid(user.uid), == 0);
        if (getuid() == 0 || getgid() == 0) //Test if uid/gid is still 0
            fprintf(stderr, "...nothing to drop. WARNING: Running as root!\n");
        else
            fprintf(stderr,"SUCCESS. UID: %d\n", getuid());
        fflush(stderr);
    }
    return;
}

//Handler

//Signal Handler for parent watchdog
void sig_handler_parent(int signo)
{
    int stat_pcap = 0;
    int stat_accept = 0;

    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s [PID %d] Received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));

    sleep(1); //Let childs exit first

    //Unlink and close semaphores
    sem_close(hdrsem);
    sem_unlink ("hdrsem");
    sem_close(consem);
    sem_unlink ("consem");
    
    //Family drama: Check if they are still alive and kill childs
    //TODO: Kill Proxys
    if ( !waitpid(accept_pid, &stat_accept, WNOHANG) )
        kill(accept_pid, SIGTERM);

    if ( !waitpid(accept_pid, &stat_accept, WNOHANG) )
        kill(pcap_pid, SIGTERM);

    for (int listenport = 1; listenport <65536; listenport++)
    {
        if ( pc->portmap[listenport] && !waitpid(pc_get_lport(pc, listenport)->pid, &stat_accept, WNOHANG) )
            kill(pc_get_lport(pc, listenport)->pid, SIGTERM);
    }

    //exit parent process
    exit(signo);
    return;
}

//Signal Handler for Listner Parent to prevent childs becoming Zombies
void sig_handler_sigchld(int signo)
{
    pid_t pid;
    int status;

    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Entering  sig_handler_sigchld(%d).\n", getpid(), signo);
    #endif
    pid = wait(&status);
    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Child with PID %d exited with status %d.\n", getpid(), pid, status);
    #endif

    do { //Search for other Childs
        pid = waitpid(-1, &status, WNOHANG);
        #if DEBUG >= 2
            if (pid > 0 ) fprintf(stderr, "*** DEBUG [PID %d] Zombie child with PID %d exited with status %d.\n", getpid(), pid, status);
        #endif
    } while ( pid > 0 );
    return;
}

//Signal Handler for childs
void sig_handler_child(int signo)
{
    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Parent died, aborting.\n", getpid());
    #endif
    abort();
    return;
}

//Signal Handler for SIGUSR1 to initiate gracefull shutdown, e.g. by CHECK-Macro
void sig_handler_shutdown(int signo)
{
    #if DEBUG >= 2
        char stop_time[64] = ""; //Human readable stop time (actual time zone)
        time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
        fprintf(stderr, "\n%s [PID %d] Received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));
    #endif
    if ( pcap_pid != 0 ) kill(pcap_pid, SIGINT);
    if ( accept_pid != 0 ) kill(accept_pid, SIGINT);
    abort();
    return;
}

//Helper functions for proxy configuration

int get_config_table(lua_State* L, char* name, struct proxy_conf_t* pc) //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.
{
    char* backendaddr = 0;
    int backendport = 0;

    int num_elements = 0;
    
    lua_getglobal(L, name); //push objekt "name" to stack and...

    if ( !lua_istable(L, -1) ) //...check if this objekt is a table
    {
        fprintf(stderr, "No proxy config found. Variable \"%s\" must be a LUA table.)\n", name);
        exit(1);
    }
    
    //Iterate over all possible portnumbers.
    //TODO: Think about a more clever solution.
    for (int listenport = 0; listenport<65536; listenport++)
    {
        //fprintf(stderr,"LOOP %d:", listenport);
        //pc_print(pc);
                
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
            
            pc_push(pc, listenport, backendaddr, backendport);
            pc->portmap[listenport] = true;
            num_elements++;
        }
        lua_pop(L, 1); //remove sub-table from stack
    }
    return num_elements;
}

struct proxy_conf_t* pc_init() //initialize proxy configuration
{
    struct proxy_conf_t* pc = malloc (sizeof(struct proxy_conf_t)); 
    pc->portlist = 0; //set headpointer to 0
    for (int listenport = 0; listenport<65536; listenport++) pc->portmap[listenport] = false; //initilze map of ports used to proxy network traffic
    return pc;
}

void pc_push(struct proxy_conf_t* pc, int listenport, char* backendaddr, int backendport) //push new proxy configuration item to linked list
{
    struct proxy_conf_node_t* pc_node = malloc (sizeof(struct proxy_conf_node_t));
    
    pc_node->listenport = listenport;
     snprintf(pc_node->listenport_str, PCN_STRLEN, "%d", listenport);
    //pc_node->backendaddr = backendaddr; //Make copy instead, to get full control over data and circumvent data corruption by free(backendaddr), etc.
    pc_node->backendaddr = malloc(strlen(backendaddr)+1);
     strncpy(pc_node->backendaddr, backendaddr, strlen(backendaddr)+1);
    pc_node->backendport = backendport;
     snprintf(pc_node->backendport_str, PCN_STRLEN, "%d", backendport);

    pc_node->pid = 0; //Set pid for proxy for this configuration to 0, because it is not running yet.

    pc_node->next = pc->portlist;
    pc->portlist = pc_node;
    pc->num_elemnts++;
    return;
}

struct proxy_conf_node_t* pc_get_lport(struct proxy_conf_t* pc, int listenport) //get proxy configuration for listenport
{
    struct proxy_conf_node_t* result = pc->portlist;
    while ( result != 0)
    {
        if(result->listenport == listenport) return result;
        result = result->next;
    }
    return 0;
}

struct proxy_conf_node_t* pc_get_pid(struct proxy_conf_t* pc, pid_t pid) //get proxy configuration for proxy with Process ID "pid"
{
    struct proxy_conf_node_t* result = pc->portlist;
    while ( result != 0)
    {
        if(result->pid == pid) return result;
        result = result->next;
    }
    return 0;
}


void pc_print(struct proxy_conf_t* pc) //print proxy configuration
{
    struct proxy_conf_node_t* pc_node = pc->portlist;
    while ( pc_node != 0)
    {
        fprintf(stderr, "\tProxy local port: %d -> Backend socket: %s:%d\n", pc_node->listenport, pc_node->backendaddr, pc_node->backendport);
        pc_node = pc_node->next;
    }
    return;
}

//Helper functions for json data structure and double linked list

struct json_data_t* jd_init()  //initialize json data structure
{
    struct json_data_t* jd = malloc (sizeof(struct json_data_t));
    jd->list = 0;
    return jd;
}

void jd_push(struct json_data_t* jd, long long unsigned int id) //push new json data list node wit id "id" to list
{
    struct json_data_node_t* jd_node = malloc (sizeof(struct json_data_node_t)); //new node

    //initialize inside variables    
    jd_node->id = id;
    jd_node->src_ip =  EMPTY_STR;
    jd_node->src_port = 0;
    jd_node->dest_ip =  EMPTY_STR;
    jd_node->dest_port =  EMPTY_STR;
    jd_node->timestamp =  EMPTY_STR;
    jd_node->unixtime =  EMPTY_STR;
    jd_node->start =  EMPTY_STR;
    jd_node->end =  EMPTY_STR;
    jd_node->bytes_toserver =  0;
    jd_node->bytes_toclient =  0;
    jd_node->proxy_ip =  EMPTY_STR;
    jd_node->proxy_port =  0;
    jd_node->backend_ip =  EMPTY_STR;
    jd_node->backend_port =  EMPTY_STR;

    //push element to beginning of list
    //TODO: More efficient, when appendig to end?
    if(jd->list != 0) jd->list->prev=jd_node;
    jd_node->next = jd->list;
    jd->list = jd_node;
    jd_node->prev = 0;

    return;
}

struct json_data_node_t* jd_get(struct json_data_t* jd, long long int id) //get json data node by id
{
    struct json_data_node_t* result = jd->list;
    while ( result != 0)
    {
        if(result->id == id) return result;
        result = result->next;
    }
    return 0;
}

bool jd_del(struct json_data_t* jd, long long int id)  //remove json data node by id
{
    struct json_data_node_t* jd_node = jd_get(jd, id);
    if (jd_node == 0) return false;

    //free all strings if not identical to initial constant string of "EMPTY_STR"
    if (jd_node->src_ip != EMPTY_STR) free(jd_node->src_ip);
    if (jd_node->dest_ip !=  EMPTY_STR) free(jd_node->dest_ip);
    if (jd_node->dest_port !=  EMPTY_STR) free(jd_node->dest_port);
    if (jd_node->timestamp !=  EMPTY_STR) free(jd_node->timestamp);
    if (jd_node->unixtime !=  EMPTY_STR) free(jd_node->unixtime);
    if (jd_node->start !=  EMPTY_STR) free(jd_node->start);
    if (jd_node->end !=  EMPTY_STR) free(jd_node->end);
    if (jd_node->proxy_ip !=  EMPTY_STR) free(jd_node->proxy_ip);
    if (jd_node->backend_ip !=  EMPTY_STR) free(jd_node->backend_ip);
    if (jd_node->backend_port !=  EMPTY_STR) free(jd_node->backend_port);

    //reorganize list pointers
    if (jd_node == jd->list) jd->list = jd_node->next; //Is it the head node?
    if (jd_node->prev != 0) jd_node->prev->next = jd_node->next;
    if (jd_node->next != 0) jd_node->next->prev = jd_node->prev;

    free(jd_node); //free the node element itself

    return true;
}

void jd_print_list(struct json_data_t* jd) //print complete json data list
{
    struct json_data_node_t* jd_node = jd->list;

    fprintf(stderr, "\n<START>\n");

    while ( jd_node != 0 )
    {
        fprintf(stderr, "\n\
long long unsigned int id: %p\n\
void* jd_node: %p\n\
struct json_data_node_t *next: %p\n\
struct json_data_node_t *prev: %p\n\
char* src_ip: %s\n\
int   src_port: %d\n\
char* dest_ip: %s\n\
char* dest_port: %s\n\
char* timestamp: %s\n\
char* unixtime: %s\n\
char* start: %s\n\
char* end: %s\n\
long long unsigned int bytes_toserver: %lld\n\
long long unsigned int bytes_toclient: %lld\n\
char* proxy_ip: %s\n\
int   proxy_port: %d\n\
char* backend_ip: %s\n\
char* backend_port: %s\n\
\n",\
(void*) jd_node->id,\
jd_node,
jd_node->next,\
jd_node->prev,\
jd_node->src_ip,\
jd_node->src_port,\
jd_node->dest_ip,\
jd_node->dest_port,\
jd_node->timestamp,\
jd_node->unixtime,\
jd_node->start,\
jd_node->end,\
jd_node->bytes_toserver,\
jd_node->bytes_toclient,\
jd_node->proxy_ip,\
jd_node->proxy_port,\
jd_node->backend_ip,\
jd_node->backend_port\
);

        jd_node = jd_node->next;
    }

    fprintf(stderr, "<END>\n\n");
    return;
}
