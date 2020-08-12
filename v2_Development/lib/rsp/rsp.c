#include "rsp.h"

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

int rsp(struct proxy_conf_node_t *pcn, char* server_addr)
{
    // Adresses / Ports / JSON data structure globally defined for easy access while logging.
    
    proxy_sock.server_addr = server_addr;
    proxy_sock.server_port_str = pcn->listenport_str;
    proxy_sock.backend_addr = pcn->backendaddr;
    proxy_sock.backend_port_str = pcn->backendport_str;
    //Initialze JSON data struct for logging
    jd = jd_init();
    
    //Make copys to prevent data corruption...
    //...Investigated and found: Making copy in pc_push(...) by strncpy(pc_node->backendaddr, backendaddr, strlen(backendaddr)+1), see there.
    //Leaving old workaround here as comment for...well, purposes...
    /*
    proxy_sock.server_addr = malloc(strlen(server_addr)+1); //strlen + \0
     strncpy(proxy_sock.server_addr, server_addr, strlen(server_addr)+1);
    proxy_sock.server_port_str = malloc(strlen(pcn->listenport_str)+1);
     strncpy(proxy_sock.server_port_str, pcn->listenport_str, strlen(pcn->listenport_str)+1);
    proxy_sock.backend_addr = malloc(strlen(pcn->backendaddr)+1);
     strncpy(proxy_sock.backend_addr, pcn->backendaddr, strlen(pcn->backendaddr)+1);
    proxy_sock.backend_port_str = malloc(strlen(pcn->backendport_str)+1);
     strncpy(proxy_sock.backend_port_str, pcn->backendport_str, strlen(pcn->backendport_str)+1);
    */

    signal(SIGPIPE, SIG_IGN);

    epoll_init();

    create_server_socket_handler(proxy_sock.server_addr,
                                 proxy_sock.server_port_str,
                                 proxy_sock.backend_addr,
                                 proxy_sock.backend_port_str);

    rsp_log("Started. Local: %s:%s -> Remote: %s:%s", proxy_sock.server_addr , proxy_sock.server_port_str, proxy_sock.backend_addr, proxy_sock.backend_port_str);
    epoll_do_reactor_loop();

    free(json_do(false, "")); //TODO: If so, free in signal handler, cause this is unreachable code.

    return 0;
}

/* Original main
int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, 
                "Usage: %s <config_file>\n", 
                argv[0]);
        exit(1);
    }

    lua_State *L = lua_open();
    if (luaL_dofile(L, argv[1]) != 0) {
        fprintf(stderr, "Error parsing config file: %s\n", lua_tostring(L, -1));
        exit(1);
    }
    char* server_port_str = get_config_opt(L, "listenPort");
    char* backend_addr = get_config_opt(L, "backendAddress");
    char* backend_port_str = get_config_opt(L, "backendPort");

    signal(SIGPIPE, SIG_IGN);

    epoll_init();

    create_server_socket_handler(server_port_str,
                                 backend_addr,
                                 backend_port_str);

    rsp_log("Started.  Listening on port %s.", server_port_str);
    epoll_do_reactor_loop();

    return 0;
}
*/
