add_test( General.Packing /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=General.Packing]==] --gtest_also_run_disabled_tests)
set_tests_properties( General.Packing PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( General.MultOneVector /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=General.MultOneVector]==] --gtest_also_run_disabled_tests)
set_tests_properties( General.MultOneVector PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( General.MultAddSub /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=General.MultAddSub]==] --gtest_also_run_disabled_tests)
set_tests_properties( General.MultAddSub PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( PKE.EncDec /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=PKE.EncDec]==] --gtest_also_run_disabled_tests)
set_tests_properties( PKE.EncDec PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( PKE.KeyLoadStoreString /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=PKE.KeyLoadStoreString]==] --gtest_also_run_disabled_tests)
set_tests_properties( PKE.KeyLoadStoreString PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( PKE.KeyLoadStoreFile /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=PKE.KeyLoadStoreFile]==] --gtest_also_run_disabled_tests)
set_tests_properties( PKE.KeyLoadStoreFile PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( PKE.CiphertextLoadStoreString /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=PKE.CiphertextLoadStoreString]==] --gtest_also_run_disabled_tests)
set_tests_properties( PKE.CiphertextLoadStoreString PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( PKE.CiphertextLoadStoreFile /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=PKE.CiphertextLoadStoreFile]==] --gtest_also_run_disabled_tests)
set_tests_properties( PKE.CiphertextLoadStoreFile PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( KEM.EncDec /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=KEM.EncDec]==] --gtest_also_run_disabled_tests)
set_tests_properties( KEM.EncDec PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( KEM.KeyLoadStoreString /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=KEM.KeyLoadStoreString]==] --gtest_also_run_disabled_tests)
set_tests_properties( KEM.KeyLoadStoreString PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( KEM.KeyLoadStoreFile /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=KEM.KeyLoadStoreFile]==] --gtest_also_run_disabled_tests)
set_tests_properties( KEM.KeyLoadStoreFile PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( KEM.CiphertextLoadStoreString /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=KEM.CiphertextLoadStoreString]==] --gtest_also_run_disabled_tests)
set_tests_properties( KEM.CiphertextLoadStoreString PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
add_test( KEM.CiphertextLoadStoreFile /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/bin/smaug5-test [==[--gtest_filter=KEM.CiphertextLoadStoreFile]==] --gtest_also_run_disabled_tests)
set_tests_properties( KEM.CiphertextLoadStoreFile PROPERTIES WORKING_DIRECTORY /home/afd/Desktop/smaug/SMAUG-reference-implementation/build/test)
set( smaug5-test_TESTS General.Packing General.MultOneVector General.MultAddSub PKE.EncDec PKE.KeyLoadStoreString PKE.KeyLoadStoreFile PKE.CiphertextLoadStoreString PKE.CiphertextLoadStoreFile KEM.EncDec KEM.KeyLoadStoreString KEM.KeyLoadStoreFile KEM.CiphertextLoadStoreString KEM.CiphertextLoadStoreFile)
