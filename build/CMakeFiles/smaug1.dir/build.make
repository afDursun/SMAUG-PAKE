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
include CMakeFiles/smaug1.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/smaug1.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/smaug1.dir/flags.make

CMakeFiles/smaug1.dir/src/dg.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/dg.c.o: ../src/dg.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/smaug1.dir/src/dg.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/dg.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/dg.c

CMakeFiles/smaug1.dir/src/dg.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/dg.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/dg.c > CMakeFiles/smaug1.dir/src/dg.c.i

CMakeFiles/smaug1.dir/src/dg.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/dg.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/dg.c -o CMakeFiles/smaug1.dir/src/dg.c.s

CMakeFiles/smaug1.dir/src/pack.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/pack.c.o: ../src/pack.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/smaug1.dir/src/pack.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/pack.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/pack.c

CMakeFiles/smaug1.dir/src/pack.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/pack.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/pack.c > CMakeFiles/smaug1.dir/src/pack.c.i

CMakeFiles/smaug1.dir/src/pack.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/pack.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/pack.c -o CMakeFiles/smaug1.dir/src/pack.c.s

CMakeFiles/smaug1.dir/src/poly.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/poly.c.o: ../src/poly.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/smaug1.dir/src/poly.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/poly.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/poly.c

CMakeFiles/smaug1.dir/src/poly.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/poly.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/poly.c > CMakeFiles/smaug1.dir/src/poly.c.i

CMakeFiles/smaug1.dir/src/poly.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/poly.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/poly.c -o CMakeFiles/smaug1.dir/src/poly.c.s

CMakeFiles/smaug1.dir/src/key.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/key.c.o: ../src/key.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/smaug1.dir/src/key.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/key.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/key.c

CMakeFiles/smaug1.dir/src/key.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/key.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/key.c > CMakeFiles/smaug1.dir/src/key.c.i

CMakeFiles/smaug1.dir/src/key.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/key.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/key.c -o CMakeFiles/smaug1.dir/src/key.c.s

CMakeFiles/smaug1.dir/src/pake.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/pake.c.o: ../src/pake.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/smaug1.dir/src/pake.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/pake.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/pake.c

CMakeFiles/smaug1.dir/src/pake.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/pake.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/pake.c > CMakeFiles/smaug1.dir/src/pake.c.i

CMakeFiles/smaug1.dir/src/pake.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/pake.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/pake.c -o CMakeFiles/smaug1.dir/src/pake.c.s

CMakeFiles/smaug1.dir/src/ciphertext.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/ciphertext.c.o: ../src/ciphertext.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/smaug1.dir/src/ciphertext.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/ciphertext.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/ciphertext.c

CMakeFiles/smaug1.dir/src/ciphertext.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/ciphertext.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/ciphertext.c > CMakeFiles/smaug1.dir/src/ciphertext.c.i

CMakeFiles/smaug1.dir/src/ciphertext.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/ciphertext.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/ciphertext.c -o CMakeFiles/smaug1.dir/src/ciphertext.c.s

CMakeFiles/smaug1.dir/src/hwt.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/hwt.c.o: ../src/hwt.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/smaug1.dir/src/hwt.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/hwt.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/hwt.c

CMakeFiles/smaug1.dir/src/hwt.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/hwt.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/hwt.c > CMakeFiles/smaug1.dir/src/hwt.c.i

CMakeFiles/smaug1.dir/src/hwt.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/hwt.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/hwt.c -o CMakeFiles/smaug1.dir/src/hwt.c.s

CMakeFiles/smaug1.dir/src/kem.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/kem.c.o: ../src/kem.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/smaug1.dir/src/kem.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/kem.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/kem.c

CMakeFiles/smaug1.dir/src/kem.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/kem.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/kem.c > CMakeFiles/smaug1.dir/src/kem.c.i

CMakeFiles/smaug1.dir/src/kem.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/kem.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/kem.c -o CMakeFiles/smaug1.dir/src/kem.c.s

CMakeFiles/smaug1.dir/src/io.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/io.c.o: ../src/io.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/smaug1.dir/src/io.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/io.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/io.c

CMakeFiles/smaug1.dir/src/io.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/io.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/io.c > CMakeFiles/smaug1.dir/src/io.c.i

CMakeFiles/smaug1.dir/src/io.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/io.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/io.c -o CMakeFiles/smaug1.dir/src/io.c.s

CMakeFiles/smaug1.dir/src/indcpa.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/indcpa.c.o: ../src/indcpa.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building C object CMakeFiles/smaug1.dir/src/indcpa.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/indcpa.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/indcpa.c

CMakeFiles/smaug1.dir/src/indcpa.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/indcpa.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/indcpa.c > CMakeFiles/smaug1.dir/src/indcpa.c.i

CMakeFiles/smaug1.dir/src/indcpa.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/indcpa.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/indcpa.c -o CMakeFiles/smaug1.dir/src/indcpa.c.s

CMakeFiles/smaug1.dir/src/hash.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/hash.c.o: ../src/hash.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building C object CMakeFiles/smaug1.dir/src/hash.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/hash.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/hash.c

CMakeFiles/smaug1.dir/src/hash.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/hash.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/hash.c > CMakeFiles/smaug1.dir/src/hash.c.i

CMakeFiles/smaug1.dir/src/hash.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/hash.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/hash.c -o CMakeFiles/smaug1.dir/src/hash.c.s

CMakeFiles/smaug1.dir/src/verify.c.o: CMakeFiles/smaug1.dir/flags.make
CMakeFiles/smaug1.dir/src/verify.c.o: ../src/verify.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building C object CMakeFiles/smaug1.dir/src/verify.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/smaug1.dir/src/verify.c.o   -c /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/verify.c

CMakeFiles/smaug1.dir/src/verify.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/smaug1.dir/src/verify.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/verify.c > CMakeFiles/smaug1.dir/src/verify.c.i

CMakeFiles/smaug1.dir/src/verify.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/smaug1.dir/src/verify.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/afd/Desktop/smaug/SMAUG-reference-implementation/src/verify.c -o CMakeFiles/smaug1.dir/src/verify.c.s

# Object files for target smaug1
smaug1_OBJECTS = \
"CMakeFiles/smaug1.dir/src/dg.c.o" \
"CMakeFiles/smaug1.dir/src/pack.c.o" \
"CMakeFiles/smaug1.dir/src/poly.c.o" \
"CMakeFiles/smaug1.dir/src/key.c.o" \
"CMakeFiles/smaug1.dir/src/pake.c.o" \
"CMakeFiles/smaug1.dir/src/ciphertext.c.o" \
"CMakeFiles/smaug1.dir/src/hwt.c.o" \
"CMakeFiles/smaug1.dir/src/kem.c.o" \
"CMakeFiles/smaug1.dir/src/io.c.o" \
"CMakeFiles/smaug1.dir/src/indcpa.c.o" \
"CMakeFiles/smaug1.dir/src/hash.c.o" \
"CMakeFiles/smaug1.dir/src/verify.c.o"

# External object files for target smaug1
smaug1_EXTERNAL_OBJECTS =

lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/dg.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/pack.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/poly.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/key.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/pake.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/ciphertext.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/hwt.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/kem.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/io.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/indcpa.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/hash.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/src/verify.c.o
lib/libsmaug1.so: CMakeFiles/smaug1.dir/build.make
lib/libsmaug1.so: lib/libRNG.so
lib/libsmaug1.so: lib/libFIPS202.so
lib/libsmaug1.so: CMakeFiles/smaug1.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Linking C shared library lib/libsmaug1.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/smaug1.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/smaug1.dir/build: lib/libsmaug1.so

.PHONY : CMakeFiles/smaug1.dir/build

CMakeFiles/smaug1.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/smaug1.dir/cmake_clean.cmake
.PHONY : CMakeFiles/smaug1.dir/clean

CMakeFiles/smaug1.dir/depend:
	cd /home/afd/Desktop/smaug/SMAUG-reference-implementation/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/CMakeFiles/smaug1.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/smaug1.dir/depend

