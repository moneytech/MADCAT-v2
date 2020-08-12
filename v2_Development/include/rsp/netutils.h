#ifndef NETUTILS_H
#define NETUTILS_H

#include "tcp_ip_port_mon.h"

extern void make_socket_non_blocking(int socket_fd);

extern int connect_to_backend(char* backend_host, char* backend_port_str);

#endif
