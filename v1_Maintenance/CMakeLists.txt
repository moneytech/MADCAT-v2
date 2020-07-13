
project(MADCAT)
cmake_minimum_required(VERSION 3.12)

set(PACKAGE_NAME MADCAT)
set(PACKAGE_VERSION 1.0)
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_BUGREPORT "heiko.folkerts@bsi.bund.de")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(UNINSTALL_SCRIPT "uninstall.sh")

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

############## GENERATE UNINSTALL SCRIPT #################
execute_process(
  COMMAND touch ${UNINSTALL_SCRIPT}
  COMMAND bash -c "echo \"\#\!/bin/bash\ncat install_manifest.txt | sudo xargs rm -v\necho \"done ...\"\n \" > ${UNINSTALL_SCRIPT}"
  COMMAND bash -c "chmod u+x ${UNINSTALL_SCRIPT}"
)

############## FINAL PROJECT CONFIG #################
# And the project header and library paths
include_directories(${CMAKE_SOURCE_DIR}/include)

# include folder lib, bin
add_subdirectory(lib)
add_subdirectory(bin)
#add_subdirectory(tests)

