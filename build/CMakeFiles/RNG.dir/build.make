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
include CMakeFiles/RNG.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/RNG.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/RNG.dir/flags.make

CMakeFiles/RNG.dir/src/rng.c.o: CMakeFiles/RNG.dir/flags.make
CMakeFiles/RNG.dir/src/rng.c.o: ../src/rng.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/RNG.dir/src/rng.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/RNG.dir/src/rng.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/rng.c

CMakeFiles/RNG.dir/src/rng.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/RNG.dir/src/rng.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/rng.c > CMakeFiles/RNG.dir/src/rng.c.i

CMakeFiles/RNG.dir/src/rng.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/RNG.dir/src/rng.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/rng.c -o CMakeFiles/RNG.dir/src/rng.c.s

# Object files for target RNG
RNG_OBJECTS = \
"CMakeFiles/RNG.dir/src/rng.c.o"

# External object files for target RNG
RNG_EXTERNAL_OBJECTS =

lib/libRNG.so: CMakeFiles/RNG.dir/src/rng.c.o
lib/libRNG.so: CMakeFiles/RNG.dir/build.make
lib/libRNG.so: /usr/lib/x86_64-linux-gnu/libcrypto.so
lib/libRNG.so: CMakeFiles/RNG.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library lib/libRNG.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/RNG.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/RNG.dir/build: lib/libRNG.so

.PHONY : CMakeFiles/RNG.dir/build

CMakeFiles/RNG.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/RNG.dir/cmake_clean.cmake
.PHONY : CMakeFiles/RNG.dir/clean

CMakeFiles/RNG.dir/depend:
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles/RNG.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/RNG.dir/depend
