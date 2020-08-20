--*******************************************************************************
-- This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
--    MADCAT is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--    MADCAT is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--    You should have received a copy of the GNU General Public License
--    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
--
--    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
--    MADCAT ist Freie Software: Sie können es unter den Bedingungen
--    der GNU General Public License, wie von der Free Software Foundation,
--    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
--    veröffentlichten Version, weiter verteilen und/oder modifizieren.
--    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
--    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
--    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
--    Siehe die GNU General Public License für weitere Details.
--    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
--    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
--*******************************************************************************/
--MADCAT - Mass Attack Detecion Connection Acceptance Tool
--TCP-IP Port Monitor v1.1.5
--Heiko Folkerts, BSI 2020
--
-- Config File
--
-- This sample config file is a merged config file for all modules (TCP-, UDP- and ICMP-(Port)Monitor).
-- This can be done if identical parameters have identical values (e.g. "hostaddress" or "user")
-- Values, which are unique to at least one module, like "path_to_save_udp-data", are ignored by other modules.
--

interface = "lo" --interface to listen on
hostaddress = "192.168.2.199" --address to listen on
listening_port = "65535" --TCP-Port to listen on
connection_timeout = "10" --Timout for TCP-Connections
user = "hf" --user to drop privileges to.
--Paths for Files containing Payload: Must end with trailing "/", will be handled as prefix otherwise.
path_to_save_tcp_streams = "./tpm/"
path_to_save_udp_data = "./upm/"
path_to_save_icmp_data = "./ipm/"
max_file_size = "10000" --optional: Max. Size for TCP-Streams to be saved or jsonized.
bufsize = "16384" --optional: Receiving Buffer size for UDP or ICMP Module
--proxy_wait_restart = "2" --time to wait before a crashed TCP proxy restarts, e.g. because backend has failed
--TCP Proxy configuration
tcpproxy = { -- [<listen port>] = { "<backend IP>", <backend Port> },
            [222]   = { "192.168.2.50", 22 },
            [2222]  = { "192.168.2.50", 222 },
            [80]    = { "192.168.2.50", 8080 },
            [64000] = { "192.168.2.50", 64000 },
           }
--UDP Proxy configuration
udpproxy_tobackend_addr = "192.168.2.199" --Local address to communicate to backends with. Mandatory, if "udpproxy" is configured.
udpproxy_connection_timeout = "5" --Timeout for UDP "Connections". Optional, but only usefull if "udpproxy" is configured.
udpproxy = { -- [<listen port>] = { "<backend IP>", <backend Port> },
            [64000] = { "192.168.2.50", 64000 },
            [533]   = { "8.8.4.4", 53},
            [534]   = { "8.8.8.8", 53},
           }
