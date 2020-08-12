#include "logging.h"

void rsp_log(char* format, ...)
{
    char log_time[64];
    time_str(NULL, 0, log_time, 64);

    fprintf(stderr, "%s [PID %d] Proxy: ", log_time, getpid()); 

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
    rsp_log("%s (%s)", message, error);
}

