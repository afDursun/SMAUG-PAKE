if(EXISTS "/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test/smaug5-test[1]_tests.cmake")
  include("/home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test/smaug5-test[1]_tests.cmake")
else()
  add_test(smaug5-test_NOT_BUILT smaug5-test_NOT_BUILT)
endif()
