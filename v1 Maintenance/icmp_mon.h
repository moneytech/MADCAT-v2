/* MADCAT - Mass Attack Detecion Connection Acceptance Tool
 * ICMP monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * Heiko Folkerts, BSI 2018-2019
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pwd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/file.h>
#include <openssl/sha.h>

#define VERSION "MADCAT - Mass Attack Detecion Connection Acceptance Tool\nICMP Monitor v1.1.4\nHeiko Folkerts, BSI 2018-2020\n"
#define MASCOTT "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n hfo   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__\n"
#define PATH_LEN 256
#define ICMP_HEADER_LEN 8
#define UDP_HEADER_LEN 8
#define IP_OR_TCP_HEADER_MINLEN 20 // Minimum Length of an IP-Header or a TCP-Header is 20 Bytes
#define DEFAULT_BUFSIZE 9000 //Ethernet jumbo frame limit
#define JSON_BUF_SIZE_BASELINE 65536 //Baseline for JSON Buffer
#define ETHERNET_HEADER_LEN 14 //Length of an Ethernet Header

#define CHECK(result, check)                                                            \
        ({                                                                 \
                typeof(result) retval = (result);                                           \
                if (!(retval check)) {                                                      \
                        fprintf(stderr, "ERROR: Return value from function call '%s' is NOT %s at %s:%d.\n\tERRNO(%d): %s\n",          \
                                        #result, #check, __FILE__, __LINE__, errno, strerror(errno)); \
                        abort();                                                        \
                }                                                                       \
                retval;                                                                     \
        })

/* IP options and ICMP types/codes as defined in Wireshark*/
//Original names cause redifinition warnings, so prefix "MY" has been added
#define MY_IPOPT_COPY              0x80

#define MY_IPOPT_CONTROL           0x00
#define MY_IPOPT_RESERVED1         0x20
#define MY_IPOPT_MEASUREMENT       0x40
#define MY_IPOPT_RESERVED2         0x60

/* REF: http://www.iana.org/assignments/ip-parameters */
#define MY_IPOPT_EOOL      (0 |MY_IPOPT_CONTROL)
#define MY_IPOPT_NOP       (1 |MY_IPOPT_CONTROL)
#define MY_IPOPT_SEC       (2 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 791/1108 */
#define MY_IPOPT_LSR       (3 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)
#define MY_IPOPT_TS        (4 |MY_IPOPT_MEASUREMENT)
#define MY_IPOPT_ESEC      (5 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 1108 */
#define MY_IPOPT_CIPSO     (6 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* draft-ietf-cipso-ipsecurity-01 */
#define MY_IPOPT_RR        (7 |MY_IPOPT_CONTROL)
#define MY_IPOPT_SID       (8 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)
#define MY_IPOPT_SSR       (9 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)
#define MY_IPOPT_ZSU       (10|MY_IPOPT_CONTROL)                  /* Zsu */
#define MY_IPOPT_MTUP      (11|MY_IPOPT_CONTROL)                  /* RFC 1063 */
#define MY_IPOPT_MTUR      (12|MY_IPOPT_CONTROL)                  /* RFC 1063 */
#define MY_IPOPT_FINN      (13|MY_IPOPT_COPY|MY_IPOPT_MEASUREMENT)   /* Finn */
#define MY_IPOPT_VISA      (14|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Estrin */
#define MY_IPOPT_ENCODE    (15|MY_IPOPT_CONTROL)                  /* VerSteeg */
#define MY_IPOPT_IMITD     (16|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Lee */
#define MY_IPOPT_EIP       (17|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 1385 */
#define MY_IPOPT_TR        (18|MY_IPOPT_MEASUREMENT)              /* RFC 1393 */
#define MY_IPOPT_ADDEXT    (19|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Ullmann IPv7 */
#define MY_IPOPT_RTRALT    (20|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 2113 */
#define MY_IPOPT_SDB       (21|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 1770 Graff */
#define MY_IPOPT_UN        (22|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Released 18-Oct-2005 */
#define MY_IPOPT_DPS       (23|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Malis */
#define MY_IPOPT_UMP       (24|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Farinacci */
#define MY_IPOPT_QS        (25|MY_IPOPT_CONTROL)                  /* RFC 4782 */
#define MY_IPOPT_EXP       (30|MY_IPOPT_CONTROL) /* RFC 4727 */

/* ICMP TYPE definitions */
#define MY_ICMP_ECHOREPLY     0
#define MY_ICMP_UNREACH       3
#define MY_ICMP_SOURCEQUENCH  4
#define MY_ICMP_REDIRECT      5
#define MY_ICMP_ALTHOST       6
#define MY_ICMP_ECHO          8
#define MY_ICMP_RTRADVERT     9
#define MY_ICMP_RTRSOLICIT   10
#define MY_ICMP_TIMXCEED     11
#define MY_ICMP_PARAMPROB    12
#define MY_ICMP_TSTAMP       13
#define MY_ICMP_TSTAMPREPLY  14
#define MY_ICMP_IREQ         15
#define MY_ICMP_IREQREPLY    16
#define MY_ICMP_MASKREQ      17
#define MY_ICMP_MASKREPLY    18
#define MY_ICMP_PHOTURIS     40
#define MY_ICMP_EXTECHO      42
#define MY_ICMP_EXTECHOREPLY 43

/* ICMP UNREACHABLE CODES*/
#define MY_ICMP_NET_UNREACH         0	/* Network Unreachable */
#define MY_ICMP_HOST_UNREACH        1	/* Host Unreachable */
#define MY_ICMP_PROT_UNREACH        2	/* Protocol Unreachable */
#define MY_ICMP_PORT_UNREACH        3	/* Port Unreachable */
#define MY_ICMP_FRAG_NEEDED         4	/* Fragmentation Needed/DF set */
#define MY_ICMP_SR_FAILED           5	/* Source Route failed */
#define MY_ICMP_NET_UNKNOWN         6
#define MY_ICMP_HOST_UNKNOWN        7
#define MY_ICMP_HOST_ISOLATED       8
#define MY_ICMP_NET_ANO             9
#define MY_ICMP_HOST_ANO           10
#define MY_ICMP_NET_UNR_TOS        11
#define MY_ICMP_HOST_UNR_TOS       12
#define MY_ICMP_PKT_FILTERED       13	/* Packet filtered */
#define MY_ICMP_PREC_VIOLATION     14	/* Precedence violation */
#define MY_ICMP_PREC_CUTOFF        15	/* Precedence cut off */

#define MY_ICMP_MIP_EXTENSION_PAD	 0
#define MY_ICMP_MIP_MOB_AGENT_ADV	16
#define MY_ICMP_MIP_PREFIX_LENGTHS	19
#define MY_ICMP_MIP_CHALLENGE	24

/*
 *  TCP option as defined in wireshark
 */
//To raise self-esteem, the prefix "MY" has also been added here.
#define MY_TCPOPT_NOP              1       /* Padding */
#define MY_TCPOPT_EOL              0       /* End of options */
#define MY_TCPOPT_MSS              2       /* Segment size negotiating */
#define MY_TCPOPT_WINDOW           3       /* Window scaling */
#define MY_TCPOPT_SACK_PERM        4       /* SACK Permitted */
//#define MY_TCPOPT_SACK             5       /* SACK Block */ //not yet implemented, thread as "tainted"
#define MY_TCPOPT_ECHO             6
#define MY_TCPOPT_ECHOREPLY        7
#define MY_TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define MY_TCPOPT_CC               11
#define MY_TCPOPT_CCNEW            12
#define MY_TCPOPT_CCECHO           13
#define MY_TCPOPT_MD5              19      /* RFC2385 */
#define MY_TCPOPT_SCPS             20      /* SCPS Capabilities */
#define MY_TCPOPT_SNACK            21      /* SCPS SNACK */
#define MY_TCPOPT_RECBOUND         22      /* SCPS Record Boundary */
#define MY_TCPOPT_CORREXP          23      /* SCPS Corruption Experienced */
#define MY_TCPOPT_QS               27      /* RFC4782 Quick-Start Response */
#define MY_TCPOPT_USER_TO          28      /* RFC5482 User Timeout Option */
//#define MY_TCPOPT_MPTCP            30      /* RFC6824 Multipath TCP */ //not yet implemented, thread as "tainted"
//#define MY_TCPOPT_TFO              34      /* RFC7413 TCP Fast Open Cookie */ //not yet implemented, thread as "tainted"
//#define MY_TCPOPT_EXP_FD           0xfd    /* Experimental, reserved */ //not yet implemented, thread as "tainted"
//#define MY_TCPOPT_EXP_FE           0xfe    /* Experimental, reserved */ //not yet implemented, thread as "tainted"
/* Non IANA registered option numbers */
//#define MY_TCPOPT_RVBD_PROBE       76      /* Riverbed probe option */ //not yet implemented, thread as "tainted"
//#define MY_TCPOPT_RVBD_TRPY        78      /* Riverbed transparency option */ //not yet implemented, thread as "tainted"

/*
 *     TCP option lengths as defined in wireshark
 */
#define MY_TCPOLEN_NOP            1
#define MY_TCPOLEN_EOL            1
#define MY_TCPOLEN_MSS            4
#define MY_TCPOLEN_WINDOW         3
#define MY_TCPOLEN_SACK_PERM      2
//#define MY_TCPOLEN_SACK_MIN       2 //not yet implemented, thread as "tainted"
#define MY_TCPOLEN_ECHO           6
#define MY_TCPOLEN_ECHOREPLY      6
#define MY_TCPOLEN_TIMESTAMP     10
#define MY_TCPOLEN_CC             6
#define MY_TCPOLEN_CCNEW          6
#define MY_TCPOLEN_CCECHO         6
#define MY_TCPOLEN_MD5           18
#define MY_TCPOLEN_SCPS           4
#define MY_TCPOLEN_SNACK          6
#define MY_TCPOLEN_RECBOUND       2
#define MY_TCPOLEN_CORREXP        2
#define MY_TCPOLEN_QS             8
#define MY_TCPOLEN_USER_TO        4
//#define MY_TCPOLEN_MPTCP_MIN      3 //not yet implemented, thread as "tainted"
//#define MY_TCPOLEN_TFO_MIN        2 //not yet implemented, thread as "tainted"
//#define MY_TCPOLEN_EXP_MIN        2 //not yet implemented, thread as "tainted"
/* Non IANA registered option numbers */
//#define MY_TCPOLEN_RVBD_PROBE_MIN 3 //not yet implemented, thread as "tainted"
//#define MY_TCPOLEN_RVBD_TRPY_MIN 16 //not yet implemented, thread as "tainted"

//Global Variables and definitions
long int JSON_BUF_SIZE = 65536; //TODO: Seriously think about necessary Buffer-Size for JSON Output
char* global_json = 0; //JSON Output defined global, to make all information visibel to functions for concatination and output.
char* json_ptr = 0; //Pointer to actuall JSON output End, to concatinate strings with sprintf().

struct ipv4icmp_t {
    uint8_t  ver;
    uint8_t  ihl;
    uint8_t  proto;
    uint32_t src_ip;
    char*    src_ip_str;
    uint32_t dst_ip;
    char*    dst_ip_str;
    void*    icmp_hdr; //Begin of the 8Byte ICMP header
    uint8_t  type;
    uint8_t  code;
    uint16_t icmp_check;
    void*    data; //Begin of ICMP data (the stuff after the 8Byte header)
    unsigned long int data_len;
};

struct user_t{
    char name[33]; //Linux user names may be up to 32 characters long + 0-Termination.
    uid_t   uid;        /* user ID */
    gid_t   gid;        /* group ID */
};

//Helper Functions:
/*
void get_user_ids(struct user_t* user) //adapted example code from manpage getpwnam(3)
void time_str(char* buf, int buf_size)
void print_hex(FILE* output, const unsigned char* buffer, int buffsize)
char *print_hex_string(const unsigned char* buffer, unsigned int buffsize) //Do not forget to free!
char *inttoa(uint32_t i_addr) //inet_ntoa e.g. converts 127.1.1.1 to 127.0.0.1. This is bad e.g. for testing.
*/
#include <icmp_mon.helper.c>

//Header Parser:
/*
bool parse_ipopt(int opt_cpclno, const char* opt_name, \
                 unsigned char** opt_ptr_ptr, const unsigned char* beginofoptions_addr, const unsigned char* endofoptions_addr)
int analyze_ip_header(const unsigned char* packet, struct pcap_pkthdr header)
bool parse_tcpopt_w_length(int opt_kind, int opt_len, const char* opt_name, \
                           unsigned char** opt_ptr_ptr, const unsigned char* beginofoptions_addr, const unsigned char* endofoptions_addr)
int analyze_udp_header(const unsigned char* packet, int recv_len)
*/
#include <icmp_mon.parser.c>

//Connection worker:
/*
int do_stuff(unsigned char* buffer, int recv_len, char* hostaddress , char* data_path)
*/
#include <icmp_mon.worker.c>

