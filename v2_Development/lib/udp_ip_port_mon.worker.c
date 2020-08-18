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
 * Heiko Folkerts, BSI 2018-2020
*/


#include "udp_ip_port_mon.worker.h"
#include "udp_ip_port_mon.helper.h"


int worker_udp(unsigned char* buffer, int recv_len, char* hostaddress , char* data_path)
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
        char log_time[64] = "";
        char log_time_unix[64] ="";
        char stop_time[64] = "";
        char stop_time_unix[64] = "";
        //beginning time
        //gettimeofday(&begin , NULL); //Get current time and...
        time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time)); //...generate string with current time
        //Proxy connection ID
        uint_least64_t id = 0;
        struct udpcon_data_node_t* uc_con = 0; //Active proxy connection matching this ID, will be 0 if none matches

        if (recv_len < 28) //Minimum 20 Byte IP Header + 8 Byte UDP Header. Should never happen.
        {
            fprintf(stderr, "%s ALERT: Paket to short for UDP over IPv4, dumping %d Bytes of data:\n", log_time, recv_len);
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
        ipv4udp.dest_ip = *(uint32_t*) (buffer+16);
        ipv4udp.dest_ip_str = inttoa(ipv4udp.dest_ip);

        //Things that should never ever happen.
        if( ipv4udp.type != 4 || ipv4udp.ihl < 20 || ipv4udp.ihl > 60 || (ipv4udp.ihl + UDP_HEADER_LEN) > recv_len  || ipv4udp.proto != 17 ) 
        {
            fprintf(stderr, "%s ALERT: Malformed Paket. Dumping %d Bytes of data:\n", log_time, recv_len);
            print_hex(stderr, buffer, recv_len);
            free(ipv4udp.src_ip_str);
            free(ipv4udp.dest_ip_str);
            return -1;
        }
        //Fetch ports by using the value from IP Header Length-Field, which has been check by the if statement above, so it should be save to use for addressing
        ipv4udp.src_port = ntohs(*(uint16_t*) (buffer + ipv4udp.ihl));
        ipv4udp.dest_port = ntohs(*(uint16_t*) (buffer + ipv4udp.ihl + sizeof(uint16_t)));
        ipv4udp.data_len = recv_len - (ipv4udp.ihl + UDP_HEADER_LEN);
        ipv4udp.data = buffer + ipv4udp.ihl + UDP_HEADER_LEN;

        id = uc_genid(ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port); //Proxy connection ID
        uc_con = uc_get(uc, id); //Active proxy connection matching this ID, will be 0 if none matches

        //Ignore Pakets, that have not been addressed to an IP given by config (host or proxy backend)
        //if(strcmp(ipv4udp.dest_ip_str, hostaddress) != 0 && strcmp("0.0.0.0", hostaddress) !=0 && uc_con == 0)
        if(strcmp(ipv4udp.dest_ip_str, hostaddress) != 0 && strcmp("0.0.0.0", hostaddress) !=0 && uc_con == 0 && strcmp("192.168.2.131", hostaddress) && strcmp("192.168.2.50", hostaddress))
        {
            //fprintf(stderr, "Received packet for %s, instead of %s Returning from worker.\n", ipv4udp.dest_ip_str, hostaddress);
            free(ipv4udp.src_ip_str);
            free(ipv4udp.dest_ip_str);
            return -1;
        }

        //Log connection
        fprintf(stderr, "\nID GENERATION: src: %s:%d dest:%s:%d id: %jx\n",\
            ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port, id);

        fprintf(stderr, "%s Received packet from %s:%u to %s:%u with %d Bytes of DATA.\n", log_time, \
            ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port, ipv4udp.data_len);

        if(pc->portmap[ipv4udp.dest_port] || uc_con != 0) //if proxy is active for this port or active proxy connection to backend exists //TODO
        {
            fprintf(stderr, "\nProxy exists: src: %s:%d dest:%s:%d id: %jx\n",\
                    ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port, id);
            struct proxy_conf_udp_node_t* pc_con = pcudp_get_lport(pc, ipv4udp.dest_port); //get proxy configuration for this connection
            if(uc_con == 0 ) //if connection does not exist, make new connection to backend
            {
                fprintf(stderr, "Connection does not exists\n");
                
                uc_con = uc_push(uc, id);
                
                //Fill udpcon node structure with data
                uc_con->src_ip = strncpy(malloc(strlen(ipv4udp.src_ip_str +1 )), ipv4udp.src_ip_str, strlen(ipv4udp.src_ip_str) +1 );
                uc_con->src_port = ipv4udp.src_port;
                uc_con->dest_ip =  strncpy(malloc(strlen(ipv4udp.dest_ip_str +1 )), ipv4udp.dest_ip_str, strlen(ipv4udp.dest_ip_str) +1 );
                uc_con->dest_port =  ipv4udp.dest_port;
                uc_con->timestamp =  strncpy(malloc(strlen(log_time_unix +1 )), log_time_unix, strlen(log_time_unix) +1 );
                uc_con->unixtime =  atoi(log_time_unix);
                uc_con->start =  strncpy(malloc(strlen(log_time_unix +1 )), log_time_unix, strlen(log_time_unix) +1 );
                uc_con->end =  strncpy(malloc(strlen(log_time_unix +1 )), log_time_unix, strlen(log_time_unix) +1 );
                uc_con->last_seen =  atoi(log_time_unix);
                uc_con->bytes_toserver =  ipv4udp.data_len;
                uc_con->bytes_toclient =  0;

                uc_con->backend_ip =  strncpy(malloc(strlen(pc_con->backendaddr) +1 ), pc_con->backendaddr, strlen(pc_con->backendaddr) +1 );
                uc_con->backend_port =  pc_con->backendport;
                uc_con->proxy_ip =  strncpy(malloc(strlen(ipv4udp.src_ip_str +1 )), ipv4udp.src_ip_str, strlen(ipv4udp.src_ip_str) +1 );
                uc_con->proxy_port =  ipv4udp.src_port;
                
                //Make socket towards backend
                uc_con->backend_socket = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
                if ( (uc_con->backend_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 )
                { 
                  fprintf(stderr, "Proxy backend socket creation failed");
                  exit(1); 
                }
                memset(uc_con->backend_socket, 0, sizeof(uc_con->backend_socket)); 
      
                // Filling backend server information 
                uc_con->backend_socket->sin_family = AF_INET;
                uc_con->backend_socket->sin_port = htons(uc_con->backend_port);
                //uc_con->backend_socket->sin_addr.s_addr = INADDR_ANY; 
                inet_pton(AF_INET, uc_con->backend_ip, &(uc_con->backend_socket->sin_addr));

                //Send received data to backend via backend-socket:
                sendto(uc_con->backend_socket_fd, ipv4udp.data, ipv4udp.data_len, 
                    MSG_CONFIRM,
                    (const struct sockaddr *) uc_con->backend_socket,  
                    sizeof( *uc_con->backend_socket ));

                //Get local proxy-client port for backend ID
                struct sockaddr local_address;
                int addr_size = sizeof(local_address);
                getsockname(uc_con->backend_socket_fd, &local_address, &addr_size);
                char* port_ptr = local_address.sa_data;

                // Get backend ID
                uc_con->id_tobackend = uc_genid(pc->proxy_ip, ((uint8_t) (*port_ptr)) * 256 + ((uint8_t) (*(port_ptr+1))), uc_con->backend_ip, uc_con->backend_port);
                fprintf(stderr, "\nBACKEND ID GENERATION: src: %s:%d dest:%s:%d id: %jx\n",\
                    uc_con->proxy_ip, uc_con->proxy_port, uc_con->backend_ip, uc_con->backend_port, uc_con->id_tobackend);

                //Make socket towards client
                uc_con->client_socket = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
                if ( (uc_con->client_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 )
                { 
                fprintf(stderr, "Proxy client socket creation failed");
                exit(1); 
                }
                memset(uc_con->client_socket, 0, sizeof(uc_con->client_socket)); 

                //Filling proxy-to-client information
                uc_con->client_socket->sin_family = AF_INET;
                uc_con->client_socket->sin_addr.s_addr = inet_addr(uc_con->proxy_ip); //destination IP for incoming packets
                uc_con->client_socket->sin_port = htons(uc_con->proxy_port); //destination port for incoming packets

                struct sockaddr_in cliaddr;
                cliaddr.sin_family = AF_INET;
                cliaddr.sin_addr.s_addr= htonl(INADDR_ANY);
                cliaddr.sin_port=htons(uc_con->dest_port); //source port for outgoing packets
                CHECK(bind(uc_con->client_socket_fd,(struct sockaddr *)&cliaddr,sizeof(cliaddr)), == 0);

                //fprintf(stderr, "\n########### PROXY: IP %s, PORT %d\n\n", uc_con->proxy_ip, uc_con->proxy_port); //XXX
            }
            else //if connection exists...
            {
                fprintf(stderr, "Connection exists\n");
                if (uc_con->id_fromclient == id ) //...and connections comes from client, forward it to backend
                {
                    fprintf(stderr, "Connection from client\n");
                    //Send received data to backend via backend-socket:
                    sendto(uc_con->backend_socket_fd, ipv4udp.data, ipv4udp.data_len, 
                    MSG_CONFIRM,
                    (const struct sockaddr *) uc_con->backend_socket,  
                    sizeof( *uc_con->backend_socket ));

                    uc_con->end =  strncpy(malloc(strlen(log_time_unix +1 )), log_time_unix, strlen(log_time_unix) +1 );
                    uc_con->last_seen =  atoi(log_time_unix);
                }

                if (uc_con->id_tobackend == id ) //...and connections comes from backend, forward it to client
                {
                    fprintf(stderr, "Connection from backend\n");
                    //Send received data to client via client-socket:
                    sendto(uc_con->client_socket_fd, ipv4udp.data, ipv4udp.data_len, 
                        MSG_CONFIRM,
                        (const struct sockaddr *) uc_con->client_socket,  
                        sizeof( *uc_con->client_socket ));
                    
                    uc_con->end =  strncpy(malloc(strlen(log_time_unix +1 )), log_time_unix, strlen(log_time_unix) +1 );
                    uc_con->last_seen =  atoi(log_time_unix);                    
                }
                
            }
            
        }
        else if(ipv4udp.data_len > 0) //if destination port is not configured for proxy and some data has been received, save the content of the datagram in a file
        {
            //Generate filename LinuxTimeStamp-milisecends_destinationAddress-destinationPort_sourceAddress-sourcePort.tpm
            sprintf(file_name, "%s%s_%s-%u_%s-%u.upm", data_path, log_time, ipv4udp.dest_ip_str, ipv4udp.dest_port, ipv4udp.src_ip_str, ipv4udp.src_port);
            file_name[PATH_LEN-1] = 0; //Enforcing PATH_LEN
            file = fopen(file_name,"wb"); //Open File
            //Write when -and only WHEN - nothing went wrong data to file
            if (file != 0) {
                fprintf(stderr, "%s FILENAME: %s\n", log_time, file_name);
                fwrite(ipv4udp.data, ipv4udp.data_len, 1, file);
                CHECK(fflush(file), == 0);
                fclose(file);
            }
            else 
            { //if somthing went wrong, log it.
                fprintf(stderr, "%s ERROR: Could not write to file %s\n", log_time, file_name);
            }
        }

        //Get current time and...
        time_str(NULL, 0, stop_time, sizeof(stop_time)); //...generate string with current time
        //Compute SHA1 of payload
        SHA1(ipv4udp.data, ipv4udp.data_len, payload_sha1);
        payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);
        //Make HexDump output out of binary payload
        payload_hd_str = hex_dump(ipv4udp.data, ipv4udp.data_len, true); //Do not forget to free! 
        payload_str = print_hex_string(ipv4udp.data, ipv4udp.data_len); //Do not forget to free!
        //Begin new global JSON output and open new JSON
        //Log connection to STDOUT in json-format (Suricata-like)
        json_do(true, "{\"origin\": \"MADCAT\", \
\"src_ip\": \"%s\", \
\"dest_port\": %d, \
\"timestamp\": \"%s\", \
\"unixtime\": %s, \
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
",\
ipv4udp.src_ip_str,\
ipv4udp.dest_port,\
log_time,\
log_time_unix,\
ipv4udp.dest_ip_str,\
ipv4udp.src_port,\
log_time,\
stop_time,\
payload_hd_str,\
payload_str,\
payload_sha1_str);

        //Analyse IP & TCP Headers and concat to global JSON
        json_do(0, ", \"bytes_toserver\": %ld}", ipv4udp.data_len);
        analyze_ip_header(buffer, recv_len);
        analyze_udp_header(buffer, recv_len);
        json_do(0, "}\n"); //close JSON object

        //free str allocated by strndup() in function char *inttoa(uint32_t i_addr)
        free(ipv4udp.src_ip_str);
        free(ipv4udp.dest_ip_str);
        free(payload_sha1_str);
        free(payload_str);
        free(payload_hd_str);
        return ipv4udp.data_len;
}

