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
CMAKE_SOURCE_DIR = /home/afd/Desktop/smaug/SMAUG-reference-implementation

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/afd/Desktop/smaug/SMAUG-reference-implementation/build

# Include any dependencies generated for this target.
include benchmark/CMakeFiles/smaug1-benchmark.dir/depend.make

# Include the progress variables for this target.
include benchmark/CMakeFiles/smaug1-benchmark.dir/progress.make

# Include the compile flags for this target's objects.
include benchmark/CMakeFiles/smaug1-benchmark.dir/flags.make

benchmark/CMakeFiles/smaug1-benchmark.dir/speed.c.o: benchmark/CMakeFiles/smaug1-benchmark.dir/flags.make
benchmark/CMakeFiles/smaug1-benchmark.dir/speed.c.o: ../benchmark/speed.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object benchmark/CMakeFiles/smaug1-benchmark.dir/speed.c.o"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1-benchmark.dir/speed.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/speed.c

benchmark/CMakeFiles/smaug1-benchmark.dir/speed.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1-benchmark.dir/speed.c.i"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/speed.c > CMakeFiles/smaug1-benchmark.dir/speed.c.i

benchmark/CMakeFiles/smaug1-benchmark.dir/speed.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1-benchmark.dir/speed.c.s"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/speed.c -o CMakeFiles/smaug1-benchmark.dir/speed.c.s

benchmark/CMakeFiles/smaug1-benchmark.dir/cpucycles.c.o: benchmark/CMakeFiles/smaug1-benchmark.dir/flags.make
benchmark/CMakeFiles/smaug1-benchmark.dir/cpucycles.c.o: ../benchmark/cpucycles.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object benchmark/CMakeFiles/smaug1-benchmark.dir/cpucycles.c.o"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1-benchmark.dir/cpucycles.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/cpucycles.c

benchmark/CMakeFiles/smaug1-benchmark.dir/cpucycles.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1-benchmark.dir/cpucycles.c.i"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/cpucycles.c > CMakeFiles/smaug1-benchmark.dir/cpucycles.c.i

benchmark/CMakeFiles/smaug1-benchmark.dir/cpucycles.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1-benchmark.dir/cpucycles.c.s"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/cpucycles.c -o CMakeFiles/smaug1-benchmark.dir/cpucycles.c.s

benchmark/CMakeFiles/smaug1-benchmark.dir/speed_print.c.o: benchmark/CMakeFiles/smaug1-benchmark.dir/flags.make
benchmark/CMakeFiles/smaug1-benchmark.dir/speed_print.c.o: ../benchmark/speed_print.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object benchmark/CMakeFiles/smaug1-benchmark.dir/speed_print.c.o"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1-benchmark.dir/speed_print.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/speed_print.c

benchmark/CMakeFiles/smaug1-benchmark.dir/speed_print.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1-benchmark.dir/speed_print.c.i"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/speed_print.c > CMakeFiles/smaug1-benchmark.dir/speed_print.c.i

benchmark/CMakeFiles/smaug1-benchmark.dir/speed_print.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1-benchmark.dir/speed_print.c.s"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark/speed_print.c -o CMakeFiles/smaug1-benchmark.dir/speed_print.c.s

# Object files for target smaug1-benchmark
smaug1__benchmark_OBJECTS = \
"CMakeFiles/smaug1-benchmark.dir/speed.c.o" \
"CMakeFiles/smaug1-benchmark.dir/cpucycles.c.o" \
"CMakeFiles/smaug1-benchmark.dir/speed_print.c.o"

# External object files for target smaug1-benchmark
smaug1__benchmark_EXTERNAL_OBJECTS =

bin/smaug1-benchmark: benchmark/CMakeFiles/smaug1-benchmark.dir/speed.c.o
bin/smaug1-benchmark: benchmark/CMakeFiles/smaug1-benchmark.dir/cpucycles.c.o
bin/smaug1-benchmark: benchmark/CMakeFiles/smaug1-benchmark.dir/speed_print.c.o
bin/smaug1-benchmark: benchmark/CMakeFiles/smaug1-benchmark.dir/build.make
bin/smaug1-benchmark: lib/libsmaug1.so
bin/smaug1-benchmark: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/smaug1-benchmark: lib/libRNG.so
bin/smaug1-benchmark: lib/libFIPS202.so
bin/smaug1-benchmark: benchmark/CMakeFiles/smaug1-benchmark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable ../bin/smaug1-benchmark"
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/smaug1-benchmark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
benchmark/CMakeFiles/smaug1-benchmark.dir/build: bin/smaug1-benchmark

.PHONY : benchmark/CMakeFiles/smaug1-benchmark.dir/build

benchmark/CMakeFiles/smaug1-benchmark.dir/clean:
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark && $(CMAKE_COMMAND) -P CMakeFiles/smaug1-benchmark.dir/cmake_clean.cmake
.PHONY : benchmark/CMakeFiles/smaug1-benchmark.dir/clean

benchmark/CMakeFiles/smaug1-benchmark.dir/depend:
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation/benchmark /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/benchmark/CMakeFiles/smaug1-benchmark.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : benchmark/CMakeFiles/smaug1-benchmark.dir/depend
