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
include CMakeFiles/FIPS202.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/FIPS202.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/FIPS202.dir/flags.make

CMakeFiles/FIPS202.dir/src/fips202.c.o: CMakeFiles/FIPS202.dir/flags.make
CMakeFiles/FIPS202.dir/src/fips202.c.o: ../src/fips202.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/FIPS202.dir/src/fips202.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/FIPS202.dir/src/fips202.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/fips202.c

CMakeFiles/FIPS202.dir/src/fips202.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/FIPS202.dir/src/fips202.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/fips202.c > CMakeFiles/FIPS202.dir/src/fips202.c.i

CMakeFiles/FIPS202.dir/src/fips202.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/FIPS202.dir/src/fips202.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/fips202.c -o CMakeFiles/FIPS202.dir/src/fips202.c.s

# Object files for target FIPS202
FIPS202_OBJECTS = \
"CMakeFiles/FIPS202.dir/src/fips202.c.o"

# External object files for target FIPS202
FIPS202_EXTERNAL_OBJECTS =

lib/libFIPS202.so: CMakeFiles/FIPS202.dir/src/fips202.c.o
lib/libFIPS202.so: CMakeFiles/FIPS202.dir/build.make
lib/libFIPS202.so: CMakeFiles/FIPS202.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library lib/libFIPS202.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/FIPS202.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/FIPS202.dir/build: lib/libFIPS202.so

.PHONY : CMakeFiles/FIPS202.dir/build

CMakeFiles/FIPS202.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/FIPS202.dir/cmake_clean.cmake
.PHONY : CMakeFiles/FIPS202.dir/clean

CMakeFiles/FIPS202.dir/depend:
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles/FIPS202.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/FIPS202.dir/depend

