/* MADCAT - Mass Attack Detecion Connection Acceptance Tool
 * ICMP monitor.
 *
 * Heiko Folkerts, BSI 2018-2019
 *
 * Compile with "gcc -I . -o icmp_mon udp_ip_port_mon.c -lcrypto"
*/

//Header includes, defintions and globals
#include <icmp_mon.h>

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
                fprintf(stderr, "%s%s\nSyntax: %s hostaddress path_to_save_icmp-data user [buffer_size]\n\tBuffer Size defaults to %d Bytes.\n \
\tPath to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\n \
\tMust be run as root, but the priviliges will be droped to user after the socket has been opened.\n", MASCOTT, VERSION, argv[0], DEFAULT_BUFSIZE);
                return -1;
        }
      
        strncpy(hostaddr, argv[1], sizeof(hostaddr)); hostaddr[sizeof(hostaddr)-1] = 0; //copy hostaddress and ensure null termination of this string. Ugly, I know.

        //copy path for icmp data and ensure null termination of this string. Ugly, again...
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

        fprintf(stderr, "%s%s\n%s Starting with hostaddress %s, bufsize is %d Byte...\n", MASCOTT, VERSION, start_time, hostaddr, bufsize);

        //Variables
        struct sockaddr_in addr; //Hostaddress
        struct sockaddr_in trgaddr; //Storage for recvfrom

        socklen_t trgaddr_len = sizeof(trgaddr);
        socklen_t addr_len = sizeof(addr);
        unsigned char* buffer = 0;
        int listenfd = CHECK(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), != -1); //create socket filedescriptor
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

                json_ptr = global_json; //Begin new global JSON output
                JSON_BUF_SIZE = JSON_BUF_SIZE_BASELINE;
                global_json[0] = 0;
                //parse buffer, log, assemble JSON, parse IP/TCP/UDP headers, do stuff...
                do_stuff(buffer, recv_len, hostaddr ,data_path);
                 //print JSON output for logging and further analysis, if JSON-Object is not empty (happens if e.g. UDP is seen by ICMP Raw Socket)
                if(strlen(global_json) > 2) {
                    fprintf(stdout,"%s\n", global_json);
                    fflush(stdout);
                }
        }

        return 0;
}

