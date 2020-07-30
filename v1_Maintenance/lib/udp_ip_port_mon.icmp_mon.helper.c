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
 * UDP port- and ICMP monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Heiko Folkerts, BSI 2018-2019
*/

#include "udp_ip_port_mon.icmp_mon.helper.h"
#include "madcat.common.h"

//saves and returns address of main buffer to be freed by signal handler
void* saved_buffer(void * buffer)
{
    static void* saved_buffer = 0;
    if (buffer != 0) saved_buffer = buffer;
    return saved_buffer;
}

//Signal Handler for gracefull shutdown
void sig_handler(int signo)
{
    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s Received Signal %s, shutting down...\n", stop_time, strsignal(signo));
    // Free receiving buffer
    free(saved_buffer(0));
    //exit parent process
    exit(signo);
    return;
}

void get_user_ids(struct user_t* user) //adapted example code from manpage getpwnam(3)
{
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    size_t bufsize;
    int s;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)          // Value was indeterminate
        bufsize = 16384;        // Should be more than enough

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

char* json_do(bool init_or_reset, const char* format, ...)
{

    static json_struct json; //static to hold data in json_struct after return from function
    static bool first_run = true;
    signed int numchars = 0; //number of chars to write
    va_list valst; //variable argument list
    va_start (valst, format);
    
    if (init_or_reset) //should the json_struct be initialized or reseted?
    {
        if (!first_run)
        {
            free(json.str);
            first_run = false;
        }
        CHECK(json.str = malloc(1), != 0);
        *json.str = 0;  //add trailing \0 (empty string)                
    }

    //get number of chars to write
    va_start (valst, format);
    numchars = vsnprintf(NULL, 0, format, valst);
    va_end(valst);
   
    //if an empty string has been provided as parameter, just return the pointer to actual string
    if (numchars == 0) return json.str;

    //allocate new memory for chars to write
    CHECK(json.str = realloc(json.str, strlen(json.str) + numchars + 1), != 0);
    
    //append chars to string
    va_start(valst, format);
    CHECK(vsnprintf(json.str + strlen(json.str), numchars + 1 , format, valst), != 0);
    va_end(valst);

    return json.str; //return pointer to (new) string
}