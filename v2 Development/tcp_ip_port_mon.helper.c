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
 * Heiko Folkerts, BSI 2018-2019
*/

//Helper functions

void get_user_ids(struct user_t* user) //adapted example code from manpage getpwnam(3)
{
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    size_t bufsize;
    int s;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)          /* Value was indeterminate */
        bufsize = 16384;        /* Should be more than enough */

    buf = CHECK(malloc(bufsize), != 0);
    if (buf == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    s = CHECK(getpwnam_r(user->name, &pwd, buf, bufsize, &result), == 0);

    user->uid = pwd.pw_uid;
    user->gid = pwd.pw_gid;
    free(buf);
    return;
}

void time_str(char* unix_buf, int unix_size, char* readable_buf, int readable_size)
{
        struct timeval tv;
        char tmbuf[readable_size];
        char tmzone[6]; //e.g. "+0100\0" is max. 6 chars

        gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string...
        strftime(tmbuf, readable_size, "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec)); //Target format: "2018-08-17T05:51:53.835934", therefore...
        strftime(tmzone, 6, "%z", localtime(&tv.tv_sec)); //...get timezone...
        //...and finally print time and ms to string, append timezone and ensure it is null terminated.
        if (readable_buf != NULL)
        {
            snprintf(readable_buf, readable_size, "%s.%06ld%s", tmbuf, tv.tv_usec, tmzone); readable_buf[readable_size-1] = 0; //Human readable string
        }
        if (unix_buf != NULL)
        {
            snprintf(unix_buf, unix_size, "%ld.%ld", tv.tv_sec, tv.tv_usec); unix_buf[unix_size-1] = 0; //Unix time incl. usec
        }
        return;
}

/*
void time_str_unix_us(char* buf, int buf_size)
{
        struct timeval tv;
        gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string
        return;
}
*/

void print_hex(FILE* output, const unsigned char* buffer, int buffsize)
{   
    int i, offset = 16; //The offset of the offset is 16. X-D
    fprintf(output, "00000000 "); //first offset
    for(i=0; i<buffsize; i++)
    {                    
        fprintf(output, "%02x ", (unsigned char) buffer[i]);
        offset++;
        if (offset % 16 == 0) {
            fprintf(output, "\n%08x ", offset);                    
        } else if (offset % 8 == 0) {
            fprintf(output, "\t");                    
        }
    }
    fprintf(output, "\n\n");
    return;
}

char *print_hex_string(const unsigned char* buffer, unsigned int buffsize) //Do not forget to free!
{   
    char* output = malloc(2*buffsize+1); //output has to be min. 2*buffsize + 1 for 2 characters per byte and null-termination.
    if(buffsize<=0) {output[0] = 0; return output;}; //return proper empty string
    int i = 0;
    for(i=0; i<buffsize; i++)
        sprintf(output+2*i, "%02x", (unsigned char) buffer[i]);
    output[2*i] = 0; //Terminate string with \0
    return output;
}

char *inttoa(uint32_t i_addr) //inet_ntoa e.g. converts 127.1.1.1 to 127.0.0.1. This is bad e.g. for testing.
{
    char str_addr[16] = "";
    //convert IP(v4)-Addresses from network byte order to string
    snprintf(str_addr, 16, "%u.%u.%u.%u", i_addr & 0x000000ff, (i_addr & 0x0000ff00) >> 8, (i_addr & 0x00ff0000) >> 16, (i_addr & 0xff000000) >> 24);
    return strndup(str_addr,16); //strndup ensures \0 termination. Do not forget to free()!
}

int init_pcap(char* dev, pcap_t **handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];// Error string 
    struct bpf_program fp;    // The compiled filter 
    char filter_exp[] = PCAP_FILTER; //The filter expression 
    bpf_u_int32 mask;    // Our netmask 
    bpf_u_int32 net;    // Our IP 
    
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
    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s [PID %d] Received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));
    sleep(1); //Let childs exit first
    //Unlink and close semaphores
    sem_close(hdrsem);
    sem_unlink ("hdrsem");
    sem_close(consem);
    sem_unlink ("consem");
    //Family drama: Kill childs
    kill(pcap_pid, SIGTERM);
    kill(accept_pid, SIGTERM);
    //exit parent process
    exit(signo);
    return;
}

//Signal Handler for Listner Parent to prevent childs becoming Zombies
void sig_handler_sigchld(int sig)
{
    pid_t pid;
    int status;

    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Entering  sig_handler_sigchld(%d).\n", getpid(), sig);
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
    //exit child process
    abort();
    //return;
}

