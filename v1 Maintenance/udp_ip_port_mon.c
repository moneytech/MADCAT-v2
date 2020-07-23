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
#include <udp_ip_port_mon.h>

//Main

int main(int argc, char *argv[])
{
       //char* global_json = 0; //JSON Output defined global, to make all information visibel to functions for concatination and output.
        global_json = malloc(JSON_BUF_SIZE);
        memset(global_json, 0, JSON_BUF_SIZE);
        json_ptr = global_json;
        //get start time
        struct timeval begin;
        char start_time[64] = "";
        gettimeofday(&begin , NULL); //Get current time and...
        time_str(start_time, sizeof(start_time)); //...generate string with current time
        
        //Parse command line
        char hostaddr[INET6_ADDRSTRLEN] = "";
        char data_path[PATH_LEN] = "";
        struct user_t user;
        int bufsize = DEFAULT_BUFSIZE;

        // Checking if number of argument is
        // 4 or 5 or not.(PROG addr port conntimeout)
        if (argc < 4 || argc > 5)
        {
                fprintf(stderr, "%s%s\nSyntax: %s hostaddress path_to_save_udp-data user [buffer_size]\n\tBuffer Size defaults to %d Bytes.\n \
\tPath to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\n \
Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.\n \
\tiptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP\n\n \
\tMust be run as root, but the priviliges will be droped to user after the socket has been opened.\n", MASCOTT, VERSION, argv[0], DEFAULT_BUFSIZE);
                return -1;
        }
      
        strncpy(hostaddr, argv[1], sizeof(hostaddr)); hostaddr[sizeof(hostaddr)-1] = 0; //copy hostaddress and ensure null termination of this string. Ugly, I know.

        //copy path for stream data and ensure null termination of this string. Ugly, again...
        strncpy(data_path, argv[2], sizeof(data_path)); data_path[sizeof(data_path)-1] = 0;

        //copy user string and ensure null termination of this string. Ugly, again...
        strncpy(user.name, argv[3], sizeof(user.name)); user.name[sizeof(user.name)-1] = 0;

        if (argc == 5) //set bufsize if given and convert to integer type.
        {
                bufsize = atoi(argv[4]);
        }

        if(bufsize < 0) //Range checks
        {
                fprintf(stderr, "Bufsize %d out of range.\n", bufsize);
                return -2;
        }

        fprintf(stderr, "%s%s\n%s Starting with hostaddress %s, bufsize is %d Byte...\n",MASCOTT, VERSION, start_time, hostaddr, bufsize);

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
        buffer = CHECK(malloc(bufsize + 1), != 0 ); //allocate buffer
        while (1) {
                memset(buffer ,0 , bufsize + 1); //zeroize buffer
                int recv_len = CHECK(recvfrom(listenfd, buffer, bufsize , 0, (struct sockaddr *) &trgaddr, &trgaddr_len), != -1); //Accept Incoming data

                json_ptr = global_json; //Begin new global JSON output and...
                JSON_BUF_SIZE = JSON_BUF_SIZE_BASELINE;
                json_ptr += snprintf(json_ptr, JSON_BUF_SIZE - (json_ptr - global_json), "{\"origin\": \"MADCAT\", "); //...open new JSON
                //parse buffer, log, fetch datagram, do stuff...
                long int data_bytes = do_stuff(buffer, recv_len, hostaddr ,data_path);
                if(data_bytes >= 0) //if nothing went wrong...                         
                {
                    //Analyse IP & TCP Headers and concat to global JSON
                    json_ptr += snprintf(json_ptr, JSON_BUF_SIZE - (json_ptr - global_json), ", \"bytes_toserver\": %ld}", data_bytes);
                    analyze_ip_header(buffer, recv_len);
                    analyze_udp_header(buffer, recv_len);
                    json_ptr += snprintf(json_ptr, JSON_BUF_SIZE - (json_ptr - global_json), "}\n"); //close JSON object
                    fprintf(stdout,"%s\n", global_json); //print json output for logging and further analysis
                    fflush(stdout);
                }
        }

        return 0;
}

