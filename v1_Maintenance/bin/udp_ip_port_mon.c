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
 * UDP port monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Compile with "gcc -I . -o udp_ip_port_mon udp_ip_port_mon.c -lcrypto"
 *
 * Heiko Folkerts, BSI 2018-2019
*/

//Header includes, defintions and globals
#include "madcat.helper.h"
#include "madcat.common.h"
#include "udp_ip_port_mon.h"
#include "udp_ip_port_mon.helper.h"
#include "udp_ip_port_mon.parser.h"
#include "udp_ip_port_mon.worker.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"
//Main

int main(int argc, char *argv[])
{
        //get start time
        struct timeval begin;
        char start_time[64] = "";
        gettimeofday(&begin , NULL); //Get current time and...
        time_str(NULL, 0, start_time, sizeof(start_time)); //...generate string with current time
        
        //Parse command line
        char hostaddr[INET6_ADDRSTRLEN] = "";
        char data_path[PATH_LEN] = "";
        struct user_t user;
        int bufsize = DEFAULT_BUFSIZE;

        CHECK(signal(SIGINT, sig_handler), != SIG_ERR); //register handler for SIGINT
        CHECK(signal(SIGTERM, sig_handler), != SIG_ERR); //register handler for SIGTERM

        //Display Mascott and Version
        fprintf(stderr, "\n%s%s\n", MASCOTT, VERSION);

        // Checking if number of argument is
        // 4 or 5 or not.(PROG addr port conntimeout)
        if (argc != 2  && (argc < 4 || argc > 5))
        {
                print_help_udp(argv[0]);
                return -1;
        }

        if (argc == 2) //read config file
        {
            lua_State *luaState = lua_open();
            if (luaL_dofile(luaState, argv[1]) != 0) {
                fprintf(stderr, "%s [PID %d] Error parsing config file: %s\n\tRun without command line arguments for help.\n", start_time, getpid(), lua_tostring(luaState, -1));
                exit(1);
            }

            fprintf(stderr, "%s Parsing config file: %s\n", start_time, argv[1]);

            fprintf(stderr, "\tHostaddress: %s\n", get_config_opt(luaState, "hostaddress"));
            strncpy(hostaddr, get_config_opt(luaState, "hostaddress"), sizeof(hostaddr)); hostaddr[sizeof(hostaddr)-1] = 0;

            strncpy(user.name, get_config_opt(luaState, "user"), sizeof(user.name)); user.name[sizeof(user.name)-1] = 0;
            fprintf(stderr, "\tuser: %s\n", get_config_opt(luaState, "user"));
            
            strncpy(data_path, get_config_opt(luaState, "path_to_save_udp_data"), sizeof(data_path)); data_path[sizeof(data_path)-1] = 0;
            fprintf(stderr, "\tpath_to_save_udp_data: %s\n", get_config_opt(luaState, "path_to_save_udp_data"));

             //check if mandatory string parameters are present, bufsize is NOT mandatory, the rest are numbers and are handled otherwise
            if(strlen(hostaddr) == 0 || strlen(user.name) == 0 || strlen(data_path) == 0)
            {
                fprintf(stderr, "%s [PID %d] Error in config file: %s\n", start_time, getpid(), argv[1]);
                print_help_udp(argv[0]);
                return -1;
            }

            if(get_config_opt(luaState, "bufsize") != 0) //if optional parameter is given, set it.
            {
                bufsize = atoi(get_config_opt(luaState, "bufsize")); //convert string type to integer type (bufsize)
                fprintf(stderr, "\tbufsize: %s\n", get_config_opt(luaState, "bufsize"));
            }

            lua_close(luaState);
        }
        else //copy legacy command line arguments to variables
        {
            strncpy(hostaddr, argv[1], sizeof(hostaddr)); hostaddr[sizeof(hostaddr)-1] = 0; //copy hostaddress and ensure null termination of this string. Ugly, I know.

            //copy path for stream data and ensure null termination of this string. Ugly, again...
            strncpy(data_path, argv[2], sizeof(data_path)); data_path[sizeof(data_path)-1] = 0;

            //copy user string and ensure null termination of this string. Ugly, again...
            strncpy(user.name, argv[3], sizeof(user.name)); user.name[sizeof(user.name)-1] = 0;

            if (argc == 5) //set bufsize if given and convert to integer type.
            {
                    bufsize = atoi(argv[4]);
            }

        }

        if(bufsize < 0) //Range checks
        {
                fprintf(stderr, "Bufsize %d out of range.\n", bufsize);
                return -2;
        }

        fprintf(stderr, "%s Starting with hostaddress %s, bufsize is %d Byte...\n", start_time, hostaddr, bufsize);

        //Variables
        struct sockaddr_in addr; //Hostaddress
        struct sockaddr_in trgaddr; //Storage for recvfrom

        socklen_t trgaddr_len = sizeof(trgaddr);
        socklen_t addr_len = sizeof(addr);
        unsigned char* buffer = 0;
        int listenfd = CHECK(socket(AF_INET, SOCK_RAW, IPPROTO_UDP), != -1); //create socket filedescriptor
        // if process is running as root, drop privileges
        if (getuid() == 0) {
            fprintf(stderr, "%s Droping priviliges to user %s...", start_time, user.name);
            get_user_ids(&user); //Get traget user UDI + GID
            CHECK(setgid(user.gid), == 0); // Drop GID first for security reasons!
            CHECK(setuid(user.uid), == 0);
            if (getuid() == 0 || getgid() == 0) //Test if uid/gid is still 0
                fprintf(stderr, "...nothing to drop. WARNING: Running as root!\n");
            else
                fprintf(stderr,"SUCCESS. UID: %d\n", getuid());
            fflush(stderr);
        }

        //Initialize address struct (Host)
        bzero(&addr, addr_len);
        addr.sin_family=AF_INET;
        CHECK(inet_aton(hostaddr, &addr.sin_addr), != 0); //set and check listening address

        //Main loop
        saved_buffer(buffer = CHECK(malloc(bufsize + 1), != 0 )); //allocate buffer and saves his address to be freed by signal handler
        while (1) {
                memset(buffer ,0 , bufsize + 1); //zeroize buffer
                int recv_len = CHECK(recvfrom(listenfd, buffer, bufsize , 0, (struct sockaddr *) &trgaddr, &trgaddr_len), != -1); //Accept Incoming data

                //Begin new global JSON output and open new JSON
                json_do(1, "{\"origin\": \"MADCAT\", ");
                //parse buffer, log, fetch datagram, do stuff...
                long int data_bytes = worker_udp(buffer, recv_len, hostaddr ,data_path);
                if(data_bytes >= 0) //if nothing went wrong...                         
                {
                    //Analyse IP & TCP Headers and concat to global JSON
                    json_do(0, ", \"bytes_toserver\": %ld}", data_bytes);
                    analyze_ip_header(buffer, recv_len);
                    analyze_udp_header(buffer, recv_len);
                    json_do(0, "}\n"); //close JSON object
                    fprintf(stdout,"%s\n", json_do(0,"")); //print json output for logging and further analysis
                    fflush(stdout);
                }
                free(json_do(0,""));
        }

        return 0;
}

