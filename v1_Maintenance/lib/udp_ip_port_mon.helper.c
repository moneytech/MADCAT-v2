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
 * Heiko Folkerts, BSI 2018-2019
*/

#include "udp_ip_port_mon.helper.h"

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

//Put HexDump like output to string: DO NOT FORGET TO FREE!
unsigned char* hex_dump(const void *addr, int len, const bool json)
{
    int i =0;
    unsigned char ascii_buff[17]; //size is 16 character + \0
    const unsigned char *pc = (const unsigned char*)addr;
    //Hex output is 3 characters per Byte e.g. "ff " for 16 Bytes per row plus offset, ascii and padding with spaces. Number of rows is len div 16 plus first row.
    int out_len = (16 * 3 + 32) * (len / 16 + 1);
    unsigned char* output = malloc(out_len); //DO NOT FORGET TO FREE!
    unsigned char* out_ptr = output;
    memset(output, 0, out_len);

    if (len == 0) {
        return output;
    }
    if (len < 0) {
        return output;
    }
    //Cap length to prevent possible overflow in output.
    //Okay. It's at 4GB...
    if (len > 0xFFFFFFFF) {
        len = 0xFFFFFFFF;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++)
    {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0)
        {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
            {
                out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"  |%s|", ascii_buff);

                if (json)
                    out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"\\n");
                else
                    out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"\n");
            }

            // Output the offset.
            out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"%08x ", i);
        } else if ((i % 8) == 0) {
            if (i != 0)
                out_ptr += snprintf(out_ptr, out_len - (out_ptr - output)," ");
        }


        // Now the hex code for the specific character.
        out_ptr += snprintf(out_ptr, out_len - (out_ptr - output)," %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            ascii_buff[i % 16] = '.';
        else if (json && pc[i] == 0x22) //Do not insert " in JSON!
            ascii_buff[i % 16] = '\'';
        else if (json && pc[i] == 0x5c) //Do not insert \ in JSON!
            ascii_buff[i % 16] = '/';
        else
            ascii_buff[i % 16] = pc[i];
        ascii_buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0)
    {
        out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"   ");
        if ((i % 8) == 0)
            out_ptr += snprintf(out_ptr, out_len - (out_ptr - output)," ");

        i++;
    }

    // And print the final ASCII bit.
    out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"  |%s|", ascii_buff);
    out_ptr = 0;    

    //printf("TEST: result size: %d, size: %ld, output:\n%s\n", (16 * 3 + 32) * (len / 16 + 1), strlen(output), output);

    return output;
}

void time_str(char* buf, int buf_size)
{
        struct timeval tv;
        //struct tm nowtm;
        char tmbuf[buf_size];
        char tmzone[6]; //e.g. "+0100\0" is max. 6 chars

        //CHECK(mktime(&nowtm), != -1);
        //printf("\n\ntm_gmtoff: %ld, tm_isdst: %d\n\n", (nowtm.tm_gmtoff / 60), nowtm.tm_isdst);

        gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string
        strftime(tmbuf, buf_size, "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec)); //Target format: "2018-08-17T05:51:53.835934 + 0200", therefore...
        strftime(tmzone, 6, "%z", localtime(&tv.tv_sec)); //...get timezone...
        //...and finally print time and ms to string, append timezone and ensure it is null terminated.
        snprintf(buf, buf_size, "%s.%06ld%s", tmbuf, tv.tv_usec, tmzone); buf[buf_size-1] = 0;
        return;
}

//convert IP(v4)-Addresses from network byte order to string
char *inttoa(uint32_t i_addr)
{
    char str_addr[16] = "";
    //convert IP(v4)-Addresses from network byte order to string
    snprintf(str_addr, 16, "%u.%u.%u.%u", i_addr & 0x000000ff, (i_addr & 0x0000ff00) >> 8, (i_addr & 0x00ff0000) >> 16, (i_addr & 0xff000000) >> 24);
    return strndup(str_addr,16); //strndup ensures \0 termination. Do not forget to free()!
}

