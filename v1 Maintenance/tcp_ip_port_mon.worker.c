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

//Listner thread

long int do_stuff(char* dst_addr, int dst_port, char* src_addr, int src_port, double timeout, char* data_path, int max_file_size, int s,\
                  char* start_time, char* start_time_unix, FILE* confifo)
{
        //on some systems, e.g. VMs, binding to a specific address does not work as expected.
        if(strcmp(dst_addr, hostaddr) != 0 && strcmp("0.0.0.0", hostaddr) !=0) //char hostaddr[INET6_ADDRSTRLEN] globally defined.
            return -1; //Filter packtes not matching hostaddress by returning from child
 
        int size_recv;
        char chunk[CHUNK_SIZE];
        char* payload = malloc(CHUNK_SIZE); //Paylaod (Binary)
        char* payload_hd_str = 0; //Payload as string in HexDump Format
        unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload
        char * payload_sha1_str = 0;
        char* global_json_old = 0; //old global_json_ptr for recalculation of json_ptr after reallocation of global_json.
        double timediff;
        struct con_status_t con_status;

        FILE *file = 0;
        char file_name[2*PATH_LEN] = ""; //double path length for concatination purposes. PATH_LEN *MUST* be enforced when combinating path and filename!
        char now_time[64] = "";
        char lastrecv_time[64] = "";

        //structures for timeout measurment
        struct timeval begin, now;
        gettimeofday(&begin, NULL);
        
        //Log connection to STDERR in readeable format
        fprintf(stderr, "%s [PID %d] CONNECTION to %s:%d from %s:%d\n", start_time, getpid(), dst_addr , dst_port, src_addr, src_port);
        
        //Begin new global JSON output and...
        json_ptr = global_json;
        memset(json_ptr, 0, JSON_BUF_SIZE);
        //Log connection in json-format (Suricata-like).
        json_ptr += snprintf(json_ptr, JSON_BUF_SIZE - (json_ptr - global_json),"{\
\"src_ip\": \"%s\", \
\"dest_port\": %d, \
\"timestamp\": \"%s\", \
\"dest_ip\": \"%s\", \
\"src_port\": %d, \
\"proto\": \"TCP\", \
\"event_type\": \"flow\", \
\"unixtime\": %s, \
",\
src_addr, \
dst_port, \
start_time, \
dst_addr, \
src_port, \
start_time_unix\
);

        //Generate connection tag to identify connection. Maximum is 28 Bytes, e.g. "123.456.789.012_43210_98765\0"
        snprintf(con_status.tag, 28, "%s_%d_%d", src_addr, dst_port, src_port);
        //initialize connection state for connection con_status by postprocessor
        snprintf(con_status.state, 16, "%s", "open");
        snprintf(con_status.reason, 16, "%s", "n/a");
        snprintf(con_status.start, 64, "%s", start_time);
        snprintf(con_status.end, 64, "%s", start_time);
        con_status.data_bytes = 0;

        //make socket non blocking
        fcntl(s, F_SETFL, O_NONBLOCK);
        while(1) //receiving loop
        {
            //get current time
            gettimeofday(&now , NULL);
            time_str(NULL, 0, now_time, sizeof(now_time)); //Get Human readable string only
            timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec); //time elapsed in seconds
            //fprintf(stderr, "\tDEBUG timediff: %lf timeout: %lf\n", timediff, timeout); //for extreme debug purposes only
            //break after timeout
            if(timediff > timeout)
            {
                snprintf(con_status.reason, 16, "%s", "timeout");
                break;
            }
            //break if max_file_size is exceeded
            if((con_status.data_bytes >= max_file_size) && max_file_size >= 0)
            {
                snprintf(con_status.reason, 16, "%s", "size exceeded");
                break;
            }
             
            memset(chunk ,0 , CHUNK_SIZE);  //clear the variable
            if((size_recv =  recv(s , chunk , CHUNK_SIZE , 0) ) <= 0)
            {
                //if nothing was received then we want to wait a little before trying again, 0.1 seconds
                usleep(100000);
            }
            else
            {
                con_status.data_bytes += size_recv; //calculate totale size received
                if (con_status.data_bytes > 0)
                {

                    if ( file == 0) //if somthing had been received and no file is open yet...
                    {
                        //...generate filename LinuxTimeStamp-milisecends_destinationAddress-destinationPort_sourceAddress-sourcePort.tpm
                        sprintf(file_name, "%s%s_%s-%d_%s-%d.tpm", data_path, start_time, dst_addr , dst_port, src_addr, src_port);
                        file_name[PATH_LEN-1] = 0; //Enforcing PATH_LEN
                        fprintf(stderr, "%s [PID %d] FILENAME: %s\n",start_time, getpid(), file_name);
                        file = fopen(file_name,"wb"); //Open File
                    }
                    //Write when -and only WHEN nothing went wrong- data in chunk to file
                    if (file != 0) {
                        fwrite(chunk, size_recv, 1, file); 
                        CHECK(fflush(file), == 0);
                        //Save Payload for JSON-Output
                        payload = realloc(payload, con_status.data_bytes); //get memory for all received bytes so far
                        memcpy(payload + con_status.data_bytes - size_recv, chunk, size_recv); //copy chunk to payload
                    }
                    else { //if somthing went wrong, abort.
                        fprintf(stderr, "%s [PID %d] ERROR: Could not write to file %s\n",now_time, getpid(), file_name);
                        free(payload);
                        abort();
                    }
                    //fprintf(stderr, "%s" , chunk); //for extreme debug purposes only
                }
                //reset beginning time
                //fprintf(stderr, "\tDEBUG: Reseting time\n"); //for extreme debug purposes only
                gettimeofday(&begin , NULL);
                time_str(NULL, 0, lastrecv_time, sizeof(lastrecv_time));
                snprintf(con_status.end, 64, "%s", lastrecv_time); //save current time as end time candidate
            }
        } //end of receiving loop
        //if a file has been opened, because a stream had been received, close its filepointer to prevent data loss.
        if (file != 0) {
            fclose(file);
            fprintf(stderr, "%s [PID %d] FILE %s closed\n", now_time, getpid(), file_name);
        }
        snprintf(con_status.state, 16, "%s", "closed");

        //Compute SHA1 of payload
        SHA1(payload, con_status.data_bytes, payload_sha1);
        payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);
        //Make HexDump output out of binary payload
        payload_hd_str = hex_dump(payload, con_status.data_bytes, true);
        //Expand JSON-Buffer
        JSON_BUF_SIZE = JSON_BUF_SIZE + strlen(payload_hd_str) + 1; //new buffer size
        global_json_old = global_json; //save actual pointer to buffer
        CHECK(global_json = realloc(global_json, JSON_BUF_SIZE), != 0); //reallocate
        json_ptr = global_json + (json_ptr - global_json_old); //recalculate json_ptr
        //Log flow information in json-format (Suricata-like)
        json_ptr += snprintf(json_ptr, JSON_BUF_SIZE - (json_ptr - global_json),"\
\"flow\": {\
\"start\": \"%s\", \
\"end\": \"%s\", \
\"state\": \"%s\", \
\"reason\": \"%s\", \
\"bytes_toserver\": %ld,\
\"payload_hd\": \"%s\",\
\"payload_sha1\": \"%s\"\
}}",\
con_status.start,\
con_status.end,\
con_status.state,\
con_status.reason,\
con_status.data_bytes,\
payload_hd_str,\
payload_sha1_str
);

        #if DEBUG >= 2
            int consem_val = -127;
            CHECK(sem_getvalue(consem, &consem_val), != -1); //Ceck
            fprintf(stderr, "*** DEBUG [PID %d] Acquire lock for output.\n", getpid());
            fprintf(stderr, "%s [PID %d] : Value of connection semaphore: %d.\n", start_time, getpid(), consem_val);
        #endif
        sem_wait(consem); //Acquire lock for output
        fprintf(confifo,"%s\n", global_json); //print json output for further analysis
        fflush(confifo);
        #if DEBUG >= 2
            fprintf(stderr, "*** DEBUG [PID %d] Release lock for output\n", getpid());
        #endif
        sem_post(consem); //release lock

        fprintf(stdout,"{\"CONNECTION\": %s}\n", global_json); //print json output for logging
        fflush(stdout);

        fprintf(stderr, "%s [PID %d] END of %s:%d from %s:%d started %s\n",now_time, getpid(), dst_addr , dst_port, src_addr, src_port, start_time);

        free(payload_sha1_str);
        free(payload_hd_str);
        free(payload);
        return con_status.data_bytes;
}
