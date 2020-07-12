# build shared or static libraries

add_library(IcmpMonCore STATIC #SHARED #STATIC
  icmp_mon.helper.c
  icmp_mon.parser.c
  icmp_mon.worker.c
)

add_library(TcpIpPortMonCore STATIC #SHARED #STATIC
 tcp_ip_port_mon.helper.c
 tcp_ip_port_mon.parser.c
 tcp_ip_port_mon.worker.c
)


add_library(UdpIpPortMonCore STATIC #SHARED #STATIC
  udp_ip_port_mon.helper.c
  udp_ip_port_mon.parser.c
  udp_ip_port_mon.worker.c
)

install(
  TARGETS
    IcmpMonCore
    TcpIpPortMonCore
    UdpIpPortMonCore
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)
