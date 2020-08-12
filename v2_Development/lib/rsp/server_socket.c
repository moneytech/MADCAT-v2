#include "rsp.h"
#include <sys/epoll.h>

#define MAX_LISTEN_BACKLOG 4096


struct server_socket_event_data {
    char* backend_addr;
    char* backend_port_str;
};

/*//MADCAT: modified and moved to rsp.h 
struct proxy_data {
    struct epoll_event_handler* client;
    struct epoll_event_handler* backend;
};
*/


void on_client_read(void* closure, char* buffer, int len)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->backend == NULL) {
        return;
    }
    connection_write(data->backend, buffer, len);
    fprintf(stderr,"\n\n+++++ %p\n\n", data->client);
    data->bytes_toserver += len; //MADCAT //TODO
}


void on_client_close(void* closure)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->backend == NULL) {
        return;
    }

    json_out(data); //MADCAT
    fprintf(stderr,"\n\n----- %p\n\n", data->client);

    connection_close(data->backend);
    data->client = NULL;
    data->backend = NULL;
    epoll_add_to_free_list(closure);
}


void on_backend_read(void* closure, char* buffer, int len)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->client == NULL) {
        return;
    }
    connection_write(data->client, buffer, len);
    
    fprintf(stderr,"\n\n+++++ %p\n\n", data->client);
    data->bytes_toclient += len; //MADCAT //TODO
}


void on_backend_close(void* closure)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->client == NULL) {
        return;
    }

    json_out(data); //MADCAT
    fprintf(stderr,"\n\n----- %p\n\n", data->client);

    connection_close(data->client);
    data->client = NULL;
    data->backend = NULL;
    epoll_add_to_free_list(closure);
}


struct proxy_data*  handle_client_connection(int client_socket_fd, 
                              char* backend_host, 
                              char* backend_port_str) 
{
    struct epoll_event_handler* client_connection;
    rsp_log("Creating connection object for incoming connection...");
    client_connection = create_connection(client_socket_fd);

    int backend_socket_fd = connect_to_backend(backend_host, backend_port_str);
    struct epoll_event_handler* backend_connection;
    rsp_log("Creating connection object for backend connection...");
    backend_connection = create_connection(backend_socket_fd);

    struct proxy_data* proxy = malloc(sizeof(struct proxy_data));
    proxy->client = client_connection;
    proxy->backend = backend_connection;

    proxy->bytes_toclient = 0; //MADCAT
    proxy->bytes_toserver = 0; //MADCAT

    fprintf(stderr,"\n\n===== %p @ %d\n\n", proxy->client, proxy_sock.client_port);

    struct connection_closure* client_closure = (struct connection_closure*) client_connection->closure;
    client_closure->on_read = on_client_read;
    client_closure->on_read_closure = proxy;
    client_closure->on_close = on_client_close;
    client_closure->on_close_closure = proxy;

    struct connection_closure* backend_closure = (struct connection_closure*) backend_connection->closure;
    backend_closure->on_read = on_backend_read;
    backend_closure->on_read_closure = proxy;
    backend_closure->on_close = on_backend_close;
    backend_closure->on_close_closure = proxy;

    return proxy; //MADCAT
}



void handle_server_socket_event(struct epoll_event_handler* self, uint32_t events)
{
    struct server_socket_event_data* closure = (struct server_socket_event_data*) self->closure;

    /*MADCAT START*/
    struct sockaddr_in claddr; //Clientaddress
    socklen_t claddr_len = sizeof(claddr);

    char start_time[64] = ""; //Human readable start time (actual time zone)
    char start_time_unix[64] = ""; //Unix timestamp (UTC)
    time_str(start_time_unix, sizeof(start_time_unix), start_time, sizeof(start_time));

    struct proxy_data* proxy;
    /*MADCAT END*/

    int client_socket_fd;
    while (1) {
        client_socket_fd = accept(self->fd, (struct sockaddr*)&claddr, &claddr_len); //MADCAT
        //client_socket_fd = accept(self->fd, NULL, NULL);
        if (client_socket_fd == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                break;
            } else {
                rsp_log_error("Could not accept");
                exit(1);
            }
        }

        //MADCAT
        proxy = handle_client_connection(client_socket_fd,
                                         closure->backend_addr,
                                         closure->backend_port_str);
    }

    //MADCAT logging
    fprintf(stderr,"\n\n#### %p\n\n", proxy->client);
    //Initialze JSON for logging
    json_do(true,"");
    //Log connection in json-format (Suricata-like).
    json_do(false, "{\
\"src_ip\": \"%s\", \
\"dest_port\": %s, \
\"timestamp\": \"%s\", \
\"dest_ip\": \"%s\", \
\"src_port\": %d, \
\"proto\": \"TCP\", \
\"event_type\": \"proxy_flow\", \
\"unixtime\": %s, \
\"flow\": { \
\"start\": \"%s\"\
", \
inet_ntoa(claddr.sin_addr), \
proxy_sock.server_port_str, \
start_time, \
proxy_sock.server_addr, \
ntohs(claddr.sin_port), \
start_time_unix, \
start_time\
);

    return;
}


//MADCAT
int create_and_bind(char* hostaddr, char* server_port_str)
{
    //Variables for listning socket
    struct sockaddr_in addr; //Hostaddress
    struct sockaddr_in trgaddr; //Storage for original destination port
    struct sockaddr_storage claddr; //Clientaddress
    char clientaddr[INET6_ADDRSTRLEN] = "";
    
    int server_port = atoi(server_port_str);

    prctl(PR_SET_PDEATHSIG, SIGTERM); //request SIGTERM if parent dies.
    CHECK(signal(SIGTERM, sig_handler_child), != SIG_ERR); //re-register handler for SIGTERM for child process
    CHECK(signal(SIGCHLD, sig_handler_sigchld), != SIG_ERR); //register handler for parents to prevent childs becoming Zombies

    accept_pid = getpid();

    socklen_t trgaddr_len = sizeof(trgaddr);
    socklen_t claddr_len = sizeof(claddr);
    socklen_t addr_len = sizeof(addr);
    int server_socket_fd = CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), != -1); //create socket filedescriptor

    //Initialize address struct (Host)
    bzero(&addr, addr_len);
    addr.sin_family=AF_INET;
    CHECK(inet_aton(hostaddr, &addr.sin_addr), != 0); //set and check listening address
    addr.sin_port = htons(server_port); //set listening port

    struct linger sl = { 1, 5 };
    int on = 1;

    CHECK(setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on)), != -1);
    CHECK(setsockopt(server_socket_fd, SOL_SOCKET, SO_LINGER, &sl, (socklen_t)sizeof(sl)), != -1);

    //Bind socket and begin listening
    CHECK(bind(server_socket_fd, (struct sockaddr*)&addr, sizeof(addr)), != -1);

    return server_socket_fd;
}

/* //Original
int create_and_bind(char* server_port_str)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* addrs;
    int getaddrinfo_error;
    getaddrinfo_error = getaddrinfo(NULL, server_port_str, &hints, &addrs);
    if (getaddrinfo_error != 0) {
        rsp_log("Couldn't find local host details: %s", gai_strerror(getaddrinfo_error));
        exit(1);
    }

    int server_socket_fd;
    struct addrinfo* addr_iter;
    for (addr_iter = addrs; addr_iter != NULL; addr_iter = addr_iter->ai_next) {
        server_socket_fd = socket(addr_iter->ai_family,
                                  addr_iter->ai_socktype,
                                  addr_iter->ai_protocol);
        if (server_socket_fd == -1) {
            continue;
        }

        int so_reuseaddr = 1;
        if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr)) != 0) {
            continue;
        }

        if (bind(server_socket_fd,
                 addr_iter->ai_addr,
                 addr_iter->ai_addrlen) == 0)
        {
            break;
        }

        close(server_socket_fd);
    }

    if (addr_iter == NULL) {
        rsp_log("Couldn't bind");
        exit(1);
    }

    freeaddrinfo(addrs);

    return server_socket_fd;
}
*/

struct epoll_event_handler* create_server_socket_handler(char* server_addr,
                                                         char* server_port_str,
                                                         char* backend_addr,
                                                         char* backend_port_str)
{

    int server_socket_fd;
    server_socket_fd = create_and_bind(server_addr, server_port_str);
    make_socket_non_blocking(server_socket_fd);

    listen(server_socket_fd, MAX_LISTEN_BACKLOG);

    struct server_socket_event_data* closure = malloc(sizeof(struct server_socket_event_data));
    closure->backend_addr = backend_addr;
    closure->backend_port_str = backend_port_str;

    struct epoll_event_handler* result = malloc(sizeof(struct epoll_event_handler));
    result->fd = server_socket_fd;
    result->handle = handle_server_socket_event;
    result->closure = closure;

    epoll_add_handler(result, EPOLLIN | EPOLLET);

    return result;
}


