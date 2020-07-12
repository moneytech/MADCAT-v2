# build Executables

add_executable(icmp_mon
  icmp_mon.c
)

add_executable(tcp_ip_port_mon
  tcp_ip_port_mon.c
)

add_executable(udp_ip_port_mon
  udp_ip_port_mon.c
)

target_link_libraries(icmp_mon
  IcmpMonCore
  ${PCAP_LIBRARY}
  OpenSSL::SSL
  pthread
)

target_link_libraries(tcp_ip_port_mon
  TcpIpPortMonCore
  ${PCAP_LIBRARY}
  OpenSSL::SSL
  pthread
)

target_link_libraries(udp_ip_port_mon
  UdpIpPortMonCore
  ${PCAP_LIBRARY}
  OpenSSL::SSL
  pthread
)


install(TARGETS
          icmp_mon
          udp_ip_port_mon
          tcp_ip_port_mon
        RUNTIME DESTINATION bin
        )