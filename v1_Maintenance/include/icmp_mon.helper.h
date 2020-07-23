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
 * ICMP monitor parser headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Heiko Folkerts, BSI 2018-2019
*/


#ifndef ICMP_MON_HELPER_H
#define ICMP_MON_HELPER_H

#include "icmp_mon.h"

//Helper Functions:
void print_help(char* progname); //print help message
const char* get_config_opt(lua_State* L, char* name); //Returns configuration items from LUA config file
void get_user_ids(struct user_t* user); //adapted example code from manpage getpwnam(3)
void time_str(char* buf, int buf_size);
void print_hex(FILE* output, const unsigned char* buffer, int buffsize);
char* json_do(bool init_or_reset, const char* format, ...); //Reset or initialize new JSON if first arguement is true and append formated string.
char *print_hex_string(const unsigned char* buffer, unsigned int buffsize); //Do not forget to free!
char *inttoa(uint32_t i_addr); //inet_ntoa e.g. converts 127.1.1.1 to 127.0.0.1. This is bad e.g. for testing.
unsigned char* hex_dump(const void *addr, int len, const bool json);
void* saved_buffer(void * buffer); //saves and returns address of main buffer to be freed by signal handler
void sig_handler(int signo); //Signal Handler for gracefull shutdown

#endif