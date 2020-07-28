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
#include "madcat.helper.c"

void print_help_tcp(char* progname) //print help message
{
    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \tinterface = \"lo\"\n\
            \thostaddress = \"127.1.1.1\"\n\
            \tlistening_port = \"65535\"\n\
            \tconnection_timeout = \"10\"\n\
            \tuser = \"hf\"\n\
            \tpath_to_save_tcp_streams = \"./tpm/\" --Must end with trailing \"/\", will be handled as prefix otherwise\n\
            \t--max_file_size = \"1024\" --optional\n\
        ", progname);

    fprintf(stderr, "\nLEGACY SYNTAX (pre v1.1.5):\n    %s interface hostaddress listening_port connection_timeout user path_to_save_tcp-streams [max_file_size]\n\
        Path to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\
        The last paramteter, max_file_size, is the maximum size of saved streams,\n\
        but the last TCP Datagramm exceeding this size will be saved anyway.\n", progname);

    fprintf(stderr,"\nExample Netfilter Rule to work properly:\n\
        iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 192.168.8.42:65535\n\
        Listening Port is 65535 and hostaddress is 192.168.8.42 in this example.\n\n\
    Must be run as root, but the priviliges will be droped to \"user\".\n\n\
    Opens two named pipes (FiFo) containing live JSON output:\n\
        \"%s\" for stream connection data, \"%s\" for header data.\n", CONNECT_FIFO, HEADER_FIFO);
    return;
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
    // Free JSON-Buffer
    free(json_do(false, ""));
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
    abort();
    return;
}

