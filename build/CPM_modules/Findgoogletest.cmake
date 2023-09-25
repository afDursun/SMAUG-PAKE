include("/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/cmake/CPM_0.34.0.cmake")
CPMAddPackage(NAME;googletest;GITHUB_REPOSITORY;google/googletest;GIT_TAG;release-1.12.0;VERSION;1.12.0;OPTIONS;INSTALL_GTEST OFF;gtest_force_shared_crt)
set(googletest_FOUND TRUE)