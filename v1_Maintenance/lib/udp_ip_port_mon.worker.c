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
 * Heiko Folkerts, BSI 2018-2019
*/


#include "udp_ip_port_mon.worker.h"
#include "udp_ip_port_mon.helper.h"


int do_stuff(unsigned char* buffer, int recv_len, char* hostaddress , char* data_path)
{
        struct ipv4udp_t ipv4udp; //struct to save IP-Header contents of intrest
        char* payload_hd_str = 0; //Payload as string in HexDump Format
        char* payload_str = 0; //Payload as string
        unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload
        char * payload_sha1_str = 0;
        char* global_json_old = 0; //old global_json_ptr for recalculation of json_ptr after reallocation of global_json.
        FILE *file = 0;
        char file_name[2*PATH_LEN] = ""; //double path length for concatination purposes. PATH_LEN *MUST* be enforced when combinating path and filename!
        struct timeval begin;
        char start_time[64] = "";
        char stop_time[64] = "";
        //beginning time
        //gettimeofday(&begin , NULL); //Get current time and...
        time_str(start_time, sizeof(start_time)); //...generate string with current time

        if (recv_len < 28) //Minimum 20 Byte IP Header + 8 Byte UDP Header. Should never happen.
        {
            fprintf(stderr, "%s ALERT: Paket to short for UDP over IPv4, dumping %d Bytes of data:\n", start_time, recv_len);
            print_hex(stderr, buffer, recv_len); //Dump malformed paket for analysis
            return -1;
        }
        //Check IPv4 Header
        ipv4udp.type = (uint8_t) (buffer[0] & 0b11110000) >> 4; //IPv4 should have set it's version field to, well, "4".
        ipv4udp.ihl = (uint8_t) ((buffer[0] & 0b00001111) * 32) / 8; //IP Header length is given in multipels of 32 bit or 4 Byte, respectivly
        ipv4udp.proto = (uint8_t) buffer[9]; //Proto should be 17 (UDP), because it's a RAW IP/UDP Socket.
        //fprintf(stderr, "%d Bytes of DATA, type: %d ihl: %d:\n", recv_len, ipv4udp.type, ipv4udp.ihl); //Debug
        //Fetch IPs and convert them to strings.
        ipv4udp.src_ip = *(uint32_t*) (buffer+12);
        ipv4udp.src_ip_str = inttoa(ipv4udp.src_ip);
        ipv4udp.dst_ip = *(uint32_t*) (buffer+16);
        ipv4udp.dst_ip_str = inttoa(ipv4udp.dst_ip);
        //Ignore Pakets, that have not been addressed to the IP given by the command line
        if(strcmp(ipv4udp.dst_ip_str, hostaddress) != 0 && strcmp("0.0.0.0", hostaddress) !=0)
        {
            //fprintf(stderr, "Received packet for %s, instead of %s Returning from child.\n", ipv4udp.dst_ip_str, hostaddress);
            free(ipv4udp.src_ip_str);
            free(ipv4udp.dst_ip_str);
            return -1;
        }
        //Things that should never ever happen.
        if( ipv4udp.type != 4 || ipv4udp.ihl < 20 || ipv4udp.ihl > 60 || (ipv4udp.ihl + UDP_HEADER_LEN) > recv_len  || ipv4udp.proto != 17 ) 
        {
            fprintf(stderr, "%s ALERT: Malformed Paket. Dumping %d Bytes of data:\n", start_time, recv_len);
            print_hex(stderr, buffer, recv_len);
            free(ipv4udp.src_ip_str);
            free(ipv4udp.dst_ip_str);
            return -1;
        }
        //Fetch ports by using the value from IP Header Length-Field, which has been check by the if statement above, so it should be save to use for addressing
        ipv4udp.src_port = ntohs(*(uint16_t*) (buffer + ipv4udp.ihl));
        ipv4udp.dst_port = ntohs(*(uint16_t*) (buffer + ipv4udp.ihl + sizeof(uint16_t)));
        ipv4udp.data_len = recv_len - (ipv4udp.ihl + UDP_HEADER_LEN);
        ipv4udp.data = buffer + ipv4udp.ihl + UDP_HEADER_LEN;
        //Log connection
        fprintf(stderr, "%s Received packet from %s:%u to %s:%u with %d Bytes of DATA.\n", start_time, \
ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dst_ip_str, ipv4udp.dst_port, ipv4udp.data_len);
        
        if(ipv4udp.data_len > 0) //if some date has been received, save the content of the datagram in a file
        {
                    //Generate filename LinuxTimeStamp-milisecends_destinationAddress-destinationPort_sourceAddress-sourcePort.tpm
                    sprintf(file_name, "%s%s_%s-%u_%s-%u.upm", data_path, start_time, ipv4udp.dst_ip_str, ipv4udp.dst_port, ipv4udp.src_ip_str, ipv4udp.src_port);
                    file_name[PATH_LEN-1] = 0; //Enforcing PATH_LEN
                    file = fopen(file_name,"wb"); //Open File
                    //Write when -and only WHEN - nothing went wrong data to file
                    if (file != 0) {
                        fprintf(stderr, "%s FILENAME: %s\n", start_time, file_name);
                        fwrite(ipv4udp.data, ipv4udp.data_len, 1, file);
                        CHECK(fflush(file), == 0);
                        fclose(file);
                    }
                    else 
                    { //if somthing went wrong, log it.
                        fprintf(stderr, "%s ERROR: Could not write to file %s\n", start_time, file_name);
                    }
        }

        //Get current time and...
        time_str(stop_time, sizeof(stop_time)); //...generate string with current time
        //Compute SHA1 of payload
        SHA1(ipv4udp.data, ipv4udp.data_len, payload_sha1);
        payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);
        //Make HexDump output out of binary payload
        payload_hd_str = hex_dump(ipv4udp.data, ipv4udp.data_len, true); //Do not forget to free! 
        payload_str = print_hex_string(ipv4udp.data, ipv4udp.data_len); //Do not forget to free!
        //Log connection to STDOUT in json-format (Suricata-like)
        json_do(0, "\
\"src_ip\": \"%s\", \
\"dest_port\": %d, \
\"timestamp\": \"%s\", \
\"dest_ip\": \"%s\", \
\"src_port\": %d, \
\"proto\": \"UDP\", \
\"event_type\": \"flow\", \
\"flow\": { \
\"start\": \"%s\", \
\"end\": \"%s\", \
\"payload_hd\": \"%s\",\
\"payload_str\": \"%s\",\
\"payload_sha1\": \"%s\"\
", ipv4udp.src_ip_str,\
ipv4udp.dst_port,\
start_time,\
ipv4udp.dst_ip_str,\
ipv4udp.src_port,\
start_time,\
stop_time,\
payload_hd_str,\
payload_str,\
payload_sha1_str);

        //free str allocated by strndup() in function char *inttoa(uint32_t i_addr)
        free(ipv4udp.src_ip_str);
        free(ipv4udp.dst_ip_str);
        free(payload_sha1_str);
        free(payload_str);
        free(payload_hd_str);
        return ipv4udp.data_len;
}

