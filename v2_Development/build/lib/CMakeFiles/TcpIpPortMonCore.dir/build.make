# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/MADCAT/MADCAT-v2/v2_Development

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/MADCAT/MADCAT-v2/v2_Development/build

# Include any dependencies generated for this target.
include lib/CMakeFiles/TcpIpPortMonCore.dir/depend.make

# Include the progress variables for this target.
include lib/CMakeFiles/TcpIpPortMonCore.dir/progress.make

# Include the compile flags for this target's objects.
include lib/CMakeFiles/TcpIpPortMonCore.dir/flags.make

lib/CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.o: lib/CMakeFiles/TcpIpPortMonCore.dir/flags.make
lib/CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.o: ../lib/madcat.helper.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/MADCAT/MADCAT-v2/v2_Development/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object lib/CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.o"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.o   -c /home/MADCAT/MADCAT-v2/v2_Development/lib/madcat.helper.c

lib/CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.i"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/MADCAT/MADCAT-v2/v2_Development/lib/madcat.helper.c > CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.i

lib/CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.s"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/MADCAT/MADCAT-v2/v2_Development/lib/madcat.helper.c -o CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.s

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.o: lib/CMakeFiles/TcpIpPortMonCore.dir/flags.make
lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.o: ../lib/tcp_ip_port_mon.helper.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/MADCAT/MADCAT-v2/v2_Development/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.o"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.o   -c /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.helper.c

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.i"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.helper.c > CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.i

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.s"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.helper.c -o CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.s

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.o: lib/CMakeFiles/TcpIpPortMonCore.dir/flags.make
lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.o: ../lib/tcp_ip_port_mon.parser.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/MADCAT/MADCAT-v2/v2_Development/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.o"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.o   -c /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.parser.c

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.i"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.parser.c > CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.i

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.s"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.parser.c -o CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.s

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.o: lib/CMakeFiles/TcpIpPortMonCore.dir/flags.make
lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.o: ../lib/tcp_ip_port_mon.worker.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/MADCAT/MADCAT-v2/v2_Development/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.o"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.o   -c /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.worker.c

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.i"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.worker.c > CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.i

lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.s"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/MADCAT/MADCAT-v2/v2_Development/lib/tcp_ip_port_mon.worker.c -o CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.s

# Object files for target TcpIpPortMonCore
TcpIpPortMonCore_OBJECTS = \
"CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.o" \
"CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.o" \
"CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.o" \
"CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.o"

# External object files for target TcpIpPortMonCore
TcpIpPortMonCore_EXTERNAL_OBJECTS =

lib/libTcpIpPortMonCore.a: lib/CMakeFiles/TcpIpPortMonCore.dir/madcat.helper.c.o
lib/libTcpIpPortMonCore.a: lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.helper.c.o
lib/libTcpIpPortMonCore.a: lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.parser.c.o
lib/libTcpIpPortMonCore.a: lib/CMakeFiles/TcpIpPortMonCore.dir/tcp_ip_port_mon.worker.c.o
lib/libTcpIpPortMonCore.a: lib/CMakeFiles/TcpIpPortMonCore.dir/build.make
lib/libTcpIpPortMonCore.a: lib/CMakeFiles/TcpIpPortMonCore.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/MADCAT/MADCAT-v2/v2_Development/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C static library libTcpIpPortMonCore.a"
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && $(CMAKE_COMMAND) -P CMakeFiles/TcpIpPortMonCore.dir/cmake_clean_target.cmake
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TcpIpPortMonCore.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
lib/CMakeFiles/TcpIpPortMonCore.dir/build: lib/libTcpIpPortMonCore.a

.PHONY : lib/CMakeFiles/TcpIpPortMonCore.dir/build

lib/CMakeFiles/TcpIpPortMonCore.dir/clean:
	cd /home/MADCAT/MADCAT-v2/v2_Development/build/lib && $(CMAKE_COMMAND) -P CMakeFiles/TcpIpPortMonCore.dir/cmake_clean.cmake
.PHONY : lib/CMakeFiles/TcpIpPortMonCore.dir/clean

lib/CMakeFiles/TcpIpPortMonCore.dir/depend:
	cd /home/MADCAT/MADCAT-v2/v2_Development/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/MADCAT/MADCAT-v2/v2_Development /home/MADCAT/MADCAT-v2/v2_Development/lib /home/MADCAT/MADCAT-v2/v2_Development/build /home/MADCAT/MADCAT-v2/v2_Development/build/lib /home/MADCAT/MADCAT-v2/v2_Development/build/lib/CMakeFiles/TcpIpPortMonCore.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : lib/CMakeFiles/TcpIpPortMonCore.dir/depend

