#ifndef SERVER_SOCKET_H
#define SERVER_SOCKET_H

#include "tcp_ip_port_mon.h"

extern struct epoll_event_handler* create_server_socket_handler(char* server_addr,
                                                                char* server_port_str,
                                                                char* backend_addr,
                                                                char* backend_port_str);

#endif