#*******************************************************************************
# This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
#    MADCAT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    MADCAT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
#
#    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
#    MADCAT ist Freie Software: Sie können es unter den Bedingungen
#    der GNU General Public License, wie von der Free Software Foundation,
#    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
#    veröffentlichten Version, weiter verteilen und/oder modifizieren.
#    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
#    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
#    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
#    Siehe die GNU General Public License für weitere Details.
#    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
#    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
#*******************************************************************************/
#
#Sirko Höer, Heiko Folkerts, BSI 2020
#

project(MADCAT)
cmake_minimum_required(VERSION 3.12)

set(PACKAGE_NAME MADCAT)
set(PACKAGE_VERSION 1.0)
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_BUGREPORT "heiko.folkerts@bsi.bund.de")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(UNINSTALL_SCRIPT "uninstall.sh")

# Common C_FLAG option
# TODO
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gdwarf-2" "--no-strict-aliasing")
set(GCC_FLAGS "-Wall" "-gdwarf-2" "-fno-strict-aliasing")

# Set directory for libraries and executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")

# Add CMake config files to build env
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# looking for dependencies
# OpenSSL
find_package(OpenSSL REQUIRED)
# PCAP Library
find_package(PCAP REQUIRED)
# Lua Library
find_package(Lua51 REQUIRED)

############## GENERATE UNINSTALL SCRIPT #################
execute_process(
  COMMAND touch ${UNINSTALL_SCRIPT}
  COMMAND bash -c "echo \"\#\!/bin/bash\ncat install_manifest.txt | sudo xargs rm -v\necho \"done ...\"\n \" > ${UNINSTALL_SCRIPT}"
  COMMAND bash -c "chmod u+x ${UNINSTALL_SCRIPT}"
)

############## FINAL PROJECT CONFIG #################
# And the project header and library paths
include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include/rsp
  ${LUA_INCLUDE_DIR}
)

# include folder lib, bin
add_subdirectory(lib)
add_subdirectory(lib/rsp)
add_subdirectory(bin)
#add_subdirectory(tests)

