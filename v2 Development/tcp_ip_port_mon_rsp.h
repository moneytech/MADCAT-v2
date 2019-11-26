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

#include <errno.h>
#include <fcntl.h>
#include <lauxlib.h>
#include <luajit.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>


#define MAX_LISTEN_BACKLOG 4096
#define BUFFER_SIZE 4096


int epoll_fd;

struct connection_closure {
    void (*on_read)(void* closure, char* buffer, int len);
    void* on_read_closure;

    void (*on_close)(void* closure);
    void* on_close_closure;
    struct data_buffer_entry* write_buffer;
};



struct data_buffer_entry {
    int is_close_message;
    char* data;
    int current_offset;
    int len;
    struct data_buffer_entry* next;
};

struct free_list_entry {
    void* block;
    struct free_list_entry* next;
};

struct free_list_entry* free_list = NULL;

struct server_socket_event_data {
    char* backend_addr;
    char* backend_port_str;
};

struct epoll_event_handler {
    int fd;
    void (*handle)(struct epoll_event_handler*, uint32_t);
    void* closure;
};

struct proxy_data {
    struct epoll_event_handler* client;
    struct epoll_event_handler* backend;
    long long int bytes_toclient; //MADCAT
    long long int bytes_toserver; //MADCAT
    char json[JSON_BUF_SIZE]; //MADCAT
    char* json_ptr; //MADCAT
};


//MADCAT START

//Adresses / Ports globally defined for easy access while logging.
char* server_port_str = 0;
char* server_addr = 0;
char* backend_addr = 0;
char* backend_port_str = 0;

//MADCAT END

int main(int argc, char* argv[]);
void connection_really_close(struct epoll_event_handler* self);
void connection_on_close_event(struct epoll_event_handler* self);
void connection_on_out_event(struct epoll_event_handler* self);
void connection_on_in_event(struct epoll_event_handler* self);
void connection_handle_event(struct epoll_event_handler* self, uint32_t events);
void add_write_buffer_entry(struct connection_closure* closure, struct data_buffer_entry* new_entry);
void connection_write(struct epoll_event_handler* self, char* data, int len);
void connection_close(struct epoll_event_handler* self);
struct epoll_event_handler* create_connection(int client_socket_fd);
void epoll_init();
void epoll_add_handler(struct epoll_event_handler* handler, uint32_t event_mask);
void epoll_remove_handler(struct epoll_event_handler* handler);
void epoll_add_to_free_list(void* block);
void epoll_do_reactor_loop();
void rsp_log(char* format, ...);
void rsp_log_error(char* message);
void make_socket_non_blocking(int socket_fd);
int connect_to_backend(char* backend_host, char* backend_port_str);
char* get_config_opt(lua_State* L, char* name);
void on_client_read(void* closure, char* buffer, int len);
void on_client_close(void* closure);
void on_backend_read(void* closure, char* buffer, int len);
void on_backend_close(void* closure);
struct proxy_data* handle_client_connection(int client_socket_fd, char* backend_host, char* backend_port_str);
void handle_server_socket_event(struct epoll_event_handler* self, uint32_t events);
int create_and_bind(char* sever_addr, char* server_port_str);
struct epoll_event_handler* create_server_socket_handler(char* sever_addr, char* server_port_str, char* backend_addr, char* backend_port_str);
//MADCAT
void json_out(struct proxy_data* data);
