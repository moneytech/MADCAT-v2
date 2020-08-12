#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>


#include "logging.h"
#include "netutils.h"


void make_socket_non_blocking(int socket_fd)
{
    int flags;

    flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        rsp_log_error("Couldn't get socket flags");
        exit(1);
    }

    flags |= O_NONBLOCK;
    if (fcntl(socket_fd, F_SETFL, flags) == -1) {
        rsp_log_error("Couldn't set socket flags");
        exit(-1);
    }
}


int connect_to_backend(char* backend_host,
                       char* backend_port_str)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int getaddrinfo_error;
    struct addrinfo* addrs;
    getaddrinfo_error = getaddrinfo(backend_host, backend_port_str, &hints, &addrs);
    if (getaddrinfo_error != 0) {
        if (getaddrinfo_error == EAI_SYSTEM) {
            rsp_log_error("Couldn't find backend (EAI_SYSTEM)");
        } else {
            rsp_log("Couldn't find backend: %s (%d)", gai_strerror(getaddrinfo_error), getaddrinfo_error);
        }
        exit(1);
    }

    int backend_socket_fd;
    struct addrinfo* addrs_iter;
    for (addrs_iter = addrs;
         addrs_iter != NULL;
         addrs_iter = addrs_iter->ai_next)
    {
        backend_socket_fd = socket(addrs_iter->ai_family,
                                   addrs_iter->ai_socktype,
                                   addrs_iter->ai_protocol);
        if (backend_socket_fd == -1) {
            continue;
        }

        if (connect(backend_socket_fd,
                    addrs_iter->ai_addr,
                    addrs_iter->ai_addrlen) != -1) {
            break;
        }


        close(backend_socket_fd);
    }

    if (addrs_iter == NULL) {
        rsp_log("Couldn't connect to backend");
        exit(1);
    }

    
    //MADCAT start
    //Get local client address and port
    struct sockaddr local_address;
    int addr_size = sizeof(local_address);
    getsockname(backend_socket_fd, &local_address, &addr_size);

    char* port_ptr = local_address.sa_data;
    char* ip_ptr = (char*) &(local_address.sa_data) + 2;
    proxy_sock.client_port = ((uint8_t) (*port_ptr)) * 256 + ((uint8_t) (*(port_ptr+1)));
    proxy_sock.client_addr = inttoa(*(uint32_t*)ip_ptr);
    
    //fprintf(stderr, "\n\n############### \n\tServer IP: %s\n\tServer PORT: %u\n\n", inttoa(*(uint32_t*)ip_ptr), proxy_sock.client_port);

    /* //Not necessary, known by config.
    port_ptr = (char*) &(addrs_iter->ai_addr->sa_data);
    ip_ptr = (char*) &(addrs_iter->ai_addr->sa_data) + 2;
    unsigned int b_port = ((uint8_t) (*port_ptr)) * 256 + ((uint8_t) (*(port_ptr+1)));
    
    //fprintf(stderr, "\n\n############### \n\tBackend IP: %s\n\tBackend PORT: %u\n\n", inttoa(*(uint32_t*)ip_ptr), b_port);
    */

    //MADCAT end

    freeaddrinfo(addrs);

    return backend_socket_fd;
}


