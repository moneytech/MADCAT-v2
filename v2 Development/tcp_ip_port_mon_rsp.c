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
/*
A Really Simple Proxy
Trying to write a fast HTTP load-balancing proxy using C just so I can understand the underpinnings of nginx and the like.

https://github.com/gpjt/rsp
http://www.gilesthomas.com/2013/08/writing-a-reverse-proxyloadbalancer-from-the-ground-up-in-c-part-0/

Copyright (c) 2013 Giles Thomas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
// gcc rsp.c -I/usr/include/luajit-2.1/ -I. -Wl,-rpath,/usr/local/lib -lluajit-5.1

int rsp(char* config_file)
{
    lua_State *L = lua_open();
    if (luaL_dofile(L, config_file) != 0) {
        fprintf(stderr, "Error parsing config file: %s\n", lua_tostring(L, -1));
        exit(1);
    }
    // Adresses / Ports globally defined for easy access while logging.
    server_port_str = get_config_opt(L, "listenPort");
    server_addr = get_config_opt(L, "listenAddress");
    backend_addr = get_config_opt(L, "backendAddress");
    backend_port_str = get_config_opt(L, "backendPort");

    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] RSP Server-Socket: %s.\n", getpid(), server_port_str);
    #endif

    signal(SIGPIPE, SIG_IGN);

    epoll_init();

    create_server_socket_handler(server_addr,
                                 server_port_str,
                                 backend_addr,
                                 backend_port_str);

    rsp_log("Started.  Listening on port %s.", server_port_str);
    epoll_do_reactor_loop();

    return 0;
}

void connection_really_close(struct epoll_event_handler* self)
{
    struct connection_closure* closure = (struct connection_closure* ) self->closure;
    struct data_buffer_entry* next;
    while (closure->write_buffer != NULL) {
        next = closure->write_buffer->next;
        if (!closure->write_buffer->is_close_message) {
            epoll_add_to_free_list(closure->write_buffer->data);
        }
        epoll_add_to_free_list(closure->write_buffer);
        closure->write_buffer = next;
    }

    epoll_remove_handler(self);
    close(self->fd);
    epoll_add_to_free_list(self->closure);
    epoll_add_to_free_list(self);
    rsp_log("Freed connection %p", self);
}


void connection_on_close_event(struct epoll_event_handler* self)
{
    struct connection_closure* closure = (struct connection_closure*) self->closure;
    if (closure->on_close != NULL) {
        closure->on_close(closure->on_close_closure);
    }
    connection_close(self);
}


void connection_on_out_event(struct epoll_event_handler* self)
{
    struct connection_closure* closure = (struct connection_closure*) self->closure;
    int written;
    int to_write;
    struct data_buffer_entry* temp;
    while (closure->write_buffer != NULL) {
        if (closure->write_buffer->is_close_message) {
            connection_really_close(self);
            return;
        }

        to_write = closure->write_buffer->len - closure->write_buffer->current_offset;
        written = write(self->fd, closure->write_buffer->data + closure->write_buffer->current_offset, to_write);
        if (written != to_write) {
            if (written == -1) {
                if (errno == ECONNRESET || errno == EPIPE) {
                    rsp_log_error("On out event write error");
                    connection_on_close_event(self);
                    return;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    rsp_log_error("Error writing to client");
                    exit(-1);
                }
                written = 0;
            }
            closure->write_buffer->current_offset += written;
            break;
        } else {
            temp = closure->write_buffer;
            closure->write_buffer = closure->write_buffer->next;
            epoll_add_to_free_list(temp->data);
            epoll_add_to_free_list(temp);
        }
    }
}


void connection_on_in_event(struct epoll_event_handler* self)
{
    struct connection_closure* closure = (struct connection_closure*) self->closure;
    char read_buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(self->fd, read_buffer, BUFFER_SIZE)) != -1 && bytes_read != 0) {
        if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }

        if (bytes_read == 0 || bytes_read == -1) {
            connection_on_close_event(self);
            return;
        }

        if (closure->on_read != NULL) {
            closure->on_read(closure->on_read_closure, read_buffer, bytes_read);
            
        }
    }
}


void connection_handle_event(struct epoll_event_handler* self, uint32_t events)
{
    if (events & EPOLLOUT) {
        connection_on_out_event(self);
    }

    if (events & EPOLLIN) {
        connection_on_in_event(self);
    }

    if ((events & EPOLLERR) | (events & EPOLLHUP) | (events & EPOLLRDHUP)) {
        connection_on_close_event(self);
    }

}


void add_write_buffer_entry(struct connection_closure* closure, struct data_buffer_entry* new_entry) 
{
    struct data_buffer_entry* last_buffer_entry;
    if (closure->write_buffer == NULL) {
        closure->write_buffer = new_entry;
    } else {
        for (last_buffer_entry=closure->write_buffer; last_buffer_entry->next != NULL; last_buffer_entry=last_buffer_entry->next)
            ;
        last_buffer_entry->next = new_entry;
    }
}


void connection_write(struct epoll_event_handler* self, char* data, int len)
{
    struct connection_closure* closure = (struct connection_closure* ) self->closure;

    int written = 0;
    if (closure->write_buffer == NULL) {
        written = write(self->fd, data, len);
        if (written == len) {
            return;
        }
    }
    if (written == -1) {
        if (errno == ECONNRESET || errno == EPIPE) {
            rsp_log_error("Connection write error");
            connection_on_close_event(self);
            return;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            rsp_log_error("Error writing to client");
            exit(-1);
        }
        written = 0;
    }

    int unwritten = len - written;
    struct data_buffer_entry* new_entry = malloc(sizeof(struct data_buffer_entry));
    new_entry->is_close_message = 0;
    new_entry->data = malloc(unwritten);
    memcpy(new_entry->data, data + written, unwritten);
    new_entry->current_offset = 0;
    new_entry->len = unwritten;
    new_entry->next = NULL;

    add_write_buffer_entry(closure, new_entry);
}


void connection_close(struct epoll_event_handler* self)
{
    struct connection_closure* closure = (struct connection_closure* ) self->closure;
    closure->on_read = NULL;
    closure->on_close = NULL;
    if (closure->write_buffer == NULL) {
        connection_really_close(self);
    } else {
        struct data_buffer_entry* new_entry = malloc(sizeof(struct data_buffer_entry));
        new_entry->is_close_message = 1;
        new_entry->next = NULL;

        add_write_buffer_entry(closure, new_entry);
    }
}


struct epoll_event_handler* create_connection(int client_socket_fd)
{
    make_socket_non_blocking(client_socket_fd);

    struct connection_closure* closure = malloc(sizeof(struct connection_closure));
    closure->write_buffer = NULL;

    struct epoll_event_handler* result = malloc(sizeof(struct epoll_event_handler));
    rsp_log("Created connection epoll handler %p", result);
    result->fd = client_socket_fd;
    result->handle = connection_handle_event;
    result->closure = closure;

    epoll_add_handler(result, EPOLLIN | EPOLLRDHUP | EPOLLET | EPOLLOUT);

    return result;
}


void epoll_init()
{
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        rsp_log_error("Couldn't create epoll FD");
        exit(1);
    }
}


void epoll_add_handler(struct epoll_event_handler* handler, uint32_t event_mask)
{
    struct epoll_event event;

    memset(&event, 0, sizeof(struct epoll_event));
    event.data.ptr = handler;
    event.events = event_mask;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, handler->fd, &event) == -1) {
        rsp_log_error("Couldn't register server socket with epoll");
        exit(-1);
    }
}


void epoll_remove_handler(struct epoll_event_handler* handler)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, handler->fd, NULL);
}


void epoll_add_to_free_list(void* block) 
{
    struct free_list_entry* entry = malloc(sizeof(struct free_list_entry));
    entry->block = block;
    entry->next = free_list;
    free_list = entry;
}


void epoll_do_reactor_loop()
{
    struct epoll_event current_epoll_event;

    while (1) {
        struct epoll_event_handler* handler;

        epoll_wait(epoll_fd, &current_epoll_event, 1, -1);
        handler = (struct epoll_event_handler*) current_epoll_event.data.ptr;
        handler->handle(handler, current_epoll_event.events);

        struct free_list_entry* temp;
        while (free_list != NULL) {
            free(free_list->block);
            temp = free_list->next;
            free(free_list);
            free_list = temp;
        }
    }

}

void rsp_log(char* format, ...)
{
    char without_ms[64];
    char with_ms[64];
    struct timeval tv;
    struct tm *tm;

    gettimeofday(&tv, NULL);
    if ((tm = localtime(&tv.tv_sec)) != NULL)
    {
        strftime(without_ms, sizeof(without_ms), "%Y-%m-%d %H:%M:%S.%%06u %z", tm);
        snprintf(with_ms, sizeof(with_ms), without_ms, tv.tv_usec);
        fprintf(stderr, "[%s] ", with_ms); 
    }

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
    rsp_log("%s: %s", message, error);
}


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
            rsp_log_error("Couldn't find backend");
        } else {
            rsp_log("Couldn't find backend: %s", gai_strerror(getaddrinfo_error));
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

    freeaddrinfo(addrs);

    return backend_socket_fd;
}


char* get_config_opt(lua_State* L, char* name) {
    lua_getglobal(L, name);
    if (!lua_isstring(L, -1)) {
        fprintf(stderr, "%s must be a string", name);
        exit(1);
    }
    return (char*) lua_tostring(L, -1);
}

void on_client_read(void* closure, char* buffer, int len)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->backend == NULL) {
        return;
    }
    connection_write(data->backend, buffer, len);
    data->bytes_toserver += len; //MADCAT //TODO
}


void on_client_close(void* closure)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->backend == NULL) {
        return;
    }

    json_out(data);

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
    data->bytes_toclient += len; //MADCAT //TODO
}


void on_backend_close(void* closure)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->client == NULL) {
        return;
    }

    json_out(data);

    connection_close(data->client);
    data->client = NULL;
    data->backend = NULL;
    epoll_add_to_free_list(closure);
}

void json_out(struct proxy_data* data)
{
    char end_time[64] = ""; //Human readable start time (actual time zone)
    time_str(NULL, 0, end_time, sizeof(end_time)); //Get Human readable string only

    data->json_ptr += snprintf(data->json_ptr, JSON_BUF_SIZE - (data->json_ptr - data->json),"\
\"end\": \"%s\", \
\"state\": \"%s\", \
\"reason\": \"%s\", \
\"bytes_toserver\": %lld, \
\"bytes_toclient\": %lld\
}}",\
end_time,\
"closed",\
"closed",\
data->bytes_toserver,\
data->bytes_toclient\
);

    #if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] JSON: %s\n", getpid(), data->json);
    #endif
}


struct proxy_data* handle_client_connection(int client_socket_fd, 
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

    return proxy;

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

        proxy = handle_client_connection(client_socket_fd,
                                         closure->backend_addr,
                                         closure->backend_port_str);
    }

    //MADCAT logging
    proxy->json_ptr = proxy->json;
    memset(proxy->json_ptr, 0, JSON_BUF_SIZE);
    //Log connection in json-format (Suricata-like).
    proxy->json_ptr += snprintf(proxy->json_ptr, JSON_BUF_SIZE - (json_ptr - proxy->json),"{\
\"src_ip\": \"%s\", \
\"dest_port\": %s, \
\"timestamp\": \"%s\", \
\"dest_ip\": \"%s\", \
\"src_port\": %d, \
\"proto\": \"TCP\", \
\"event_type\": \"proxy_flow\", \
\"unixtime\": %s, \
\"flow\": { \
\"start\": \"%s\" \
", \
inet_ntoa(claddr.sin_addr), \
server_port_str, \
start_time, \
server_addr, \
ntohs(claddr.sin_port), \
start_time_unix, \
start_time\
);

    return;
}

int create_and_bind(char* hostaddr, char* server_port_str) //MADCAT
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

/* OLD
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


