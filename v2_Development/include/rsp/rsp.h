#include "tcp_ip_port_mon.h"
#include "epollinterface.h"
#include "logging.h"
#include "server_socket.h"


#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "madcat.helper.h"

char* get_config(lua_State* L, char* name);