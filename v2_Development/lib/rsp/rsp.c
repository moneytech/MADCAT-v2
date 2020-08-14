#include "rsp.h"

int rsp(struct proxy_conf_node_t *pcn, char* server_addr)
{
    // Adresses / Ports / JSON data structure globally defined for easy access while logging.
    
    proxy_sock.server_addr = server_addr;
    proxy_sock.server_port_str = pcn->listenport_str;
    proxy_sock.backend_addr = pcn->backendaddr;
    proxy_sock.backend_port_str = pcn->backendport_str;

    rsp_log("Starting. Local: %s:%s -> Remote: %s:%s", proxy_sock.server_addr , proxy_sock.server_port_str, proxy_sock.backend_addr, proxy_sock.backend_port_str);

    //Initialze JSON data struct for logging
    jd = jd_init();
    
    signal(SIGPIPE, SIG_IGN);

    epoll_init();

    create_server_socket_handler(proxy_sock.server_addr,
                                 proxy_sock.server_port_str,
                                 proxy_sock.backend_addr,
                                 proxy_sock.backend_port_str);

   
    epoll_do_reactor_loop();

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
