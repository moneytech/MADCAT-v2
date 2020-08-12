#ifndef LOGGING_H
#define LOGGING_H

#include "tcp_ip_port_mon.h"
/*
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
*/

extern void rsp_log(char* format, ...);

extern void rsp_log_error(char* message);

#endif