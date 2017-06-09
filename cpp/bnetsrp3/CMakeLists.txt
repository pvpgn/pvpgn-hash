include_directories(${ZLIB_INCLUDE_DIR})

add_executable(bnchat bnchat.cpp client.cpp client.h client_connect.cpp 
	client_connect.h udptest.cpp udptest.h ansi_term.h)
target_link_libraries(bnchat common compat ${NETWORK_LIBRARIES})

add_executable(bnftp bnftp.cpp client.cpp client.h)
target_link_libraries(bnftp common compat ${NETWORK_LIBRARIES})

add_executable(bnbot bnbot.cpp client.cpp client.h)
target_link_libraries(bnbot common compat ${NETWORK_LIBRARIES})

add_executable(bnstat bnstat.cpp client.cpp client.h client_connect.cpp 
	client_connect.h udptest.cpp udptest.h)
target_link_libraries(bnstat common compat ${NETWORK_LIBRARIES})

add_executable(BnetSRP3 BnetSRP3.cpp)
target_link_libraries(BnetSRP3 common compat ${NETWORK_LIBRARIES})

install(TARGETS bnchat bnftp bnbot bnstat DESTINATION ${BINDIR})
