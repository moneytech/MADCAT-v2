#ifndef RSP_H
#define RSP_H

#include "tcp_ip_port_mon.h"
#include "tcp_ip_port_mon.helper.h"

#include "epollinterface.h"
#include "logging.h"
#include "server_socket.h"
#include "netutils.h"
#include "connection.h"

struct proxy_data {
    struct epoll_event_handler* client;
    struct epoll_event_handler* backend;
    long long int bytes_toclient; //MADCAT
    long long int bytes_toserver; //MADCAT
};

//MADCAT
struct proxy_socket_t { //Adresses and ports globally defined for easy access for configuration and logging purposes.
    //remote socket
    char* backend_addr;
    char* backend_port_str;
    //lokal socket for incoming connections
    char* server_addr;
    char* server_port_str;
    //lokal socket for outgoint connections for logging purposes only, values are assigned in "int connect_to_backend(char* backend_host, char* backend_port_str)
    char* client_addr;
    u_int16_t client_port;
} proxy_sock;

int rsp(struct proxy_conf_node_t* pcn, char* server_addr);
void json_out(struct json_data_t* jd, long long int id);

#endif