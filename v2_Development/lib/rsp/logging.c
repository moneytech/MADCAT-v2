#include "logging.h"

void rsp_log(char* format, ...)
{
    char log_time[64];
    time_str(NULL, 0, log_time, 64);

    fprintf(stderr, "%s [PID %d] Proxy: ", log_time, getpid()); 

    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);

    fprintf(stderr, "\n");

    fflush(stderr);
}


void rsp_log_error(char* message)
{
    char* error = strerror(errno);
    rsp_log("%s (%s)", message, error);
}

void json_out(struct json_data_t* jd, long long int id)
{
    char end_time[64] = ""; //Human readable start time (actual time zone)
    time_str(NULL, 0, end_time, sizeof(end_time)); //Get Human readable string only

    //Log second part of connection in json data list, using struct epoll_event_handler* client as id.
    //Not realy necassary at this point, but now I've build the struct, so I decided to use it. May be usefull in further development.
    if ( !jd_get(jd, id) ) return;

    jd_get(jd, id)->end = strncpy(malloc(strlen(end_time) +1 ), end_time, strlen(end_time) +1 );

    #if DEBUG >= 2
        jd_print_list(jd);
    #endif

    //using json_do for composing of the json output

    //initialize and fill
    json_do(true, "{\
\"src_ip\": \"%s\", \
\"dest_port\": %s, \
\"timestamp\": \"%s\", \
\"dest_ip\": \"%s\", \
\"src_port\": %d, \
\"proto\": \"%s\", \
\"event_type\": \"%s\", \
\"unixtime\": %s, \
\"flow\": { \
\"start\": \"%s\",\
\"end\": \"%s\", \
\"state\": \"%s\", \
\"reason\": \"%s\", \
\"bytes_toserver\": %lld, \
\"bytes_toclient\": %lld, \
\"proxy_ip\": \"%s\", \
\"proxy_port\": %u, \
\"backend_ip\": \"%s\", \
\"backend_port\": %s\
}}",\
jd_get(jd, id)->src_ip, \
jd_get(jd, id)->dest_port, \
jd_get(jd, id)->start, \
jd_get(jd, id)->dest_ip, \
jd_get(jd, id)->src_port, \
"TCP",\
"proxy_flow",\
jd_get(jd, id)->unixtime, \
jd_get(jd, id)->start,\
jd_get(jd, id)->end,\
"closed",\
"closed",\
jd_get(jd, id)->bytes_toserver,\
jd_get(jd, id)->bytes_toclient,\
jd_get(jd, id)->proxy_ip,\
jd_get(jd, id)->proxy_port,\
jd_get(jd, id)->backend_ip,\
jd_get(jd, id)->backend_port\
);

    #if DEBUG >= 2
        int consem_val = -127;
        CHECK(sem_getvalue(consem, &consem_val), != -1); //Ceck
        fprintf(stderr, "*** DEBUG [PID %d] Acquire lock for output.\n", getpid());
        rsp_log("Value of connection semaphore: %d.\n", consem_val);
    #endif
    sem_wait(consem); //Acquire lock for output
    fprintf(confifo,"%s\n", json_do(false, "")); //print json output for further analysis
    fflush(confifo);
    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Release lock for output\n", getpid());
    #endif
    sem_post(consem); //release lock
    fprintf(stdout,"{\"CONNECTION\": %s}\n", json_do(false, "")); //print json output for logging
    fflush(confifo);
    fflush(stdout);
    //Remove and thereby free list element with id "id"
    jd_del(jd, id);
    //free json
    free(json_do(false, ""));

    return;
}
