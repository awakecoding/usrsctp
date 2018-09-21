cmake_minimum_required(VERSION 3.0)

project(usrsctp C)

include(CheckFunctionExists)
include(CheckStructHasMember)
include(CheckIncludeFile)
include(CMakePushCheckState)
include(CheckTypeSize)

set(VERSION "1.0.0")

set(USRSCTP_DEFINITIONS "")

check_include_file(sys/queue.h HAVE_SYS_QUEUE_H)
if(HAVE_SYS_QUEUE_H)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_SYS_QUEUE_H)
endif()

check_include_file(linux/if_addr.h HAVE_LINUX_IF_ADDR_H)
if(HAVE_LINUX_IF_ADDR_H)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_LINUX_IF_ADDR_H)
endif()

check_include_file(linux/rtnetlink.h HAVE_LINUX_RTNETLINK_H)
if(HAVE_LINUX_RTNETLINK_H)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_LINUX_RTNETLINK_H)
endif()

check_include_file(netinet/ip_icmp.h HAVE_NETINET_IP_ICMP_H)
if(HAVE_NETINET_IP_ICMP_H)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_NETINET_IP_ICMP_H)
endif()

check_include_file(stdatomic.h HAVE_STDATOMIC_H)
if(HAVE_STDATOMIC_H)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_STDATOMIC_H)
endif()

list(APPEND USRSCTP_DEFINITIONS -D__Userspace__)

if(${CMAKE_SYSTEM_NAME} MATCHES "WindowsStore")
	list(APPEND USRSCTP_DEFINITIONS -D__Userspace_os_UWP)
	list(APPEND USRSCTP_DEFINITIONS -D__Userspace_os_Windows)
else()
	list(APPEND USRSCTP_DEFINITIONS -D__Userspace_os_${CMAKE_SYSTEM_NAME})
endif()

list(APPEND USRSCTP_DEFINITIONS -D_GNU_SOURCE)

check_struct_has_member("struct sockaddr" "sa_len" "sys/types.h;sys/socket.h" HAVE_SA_LEN)
if(HAVE_SA_LEN)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_SA_LEN)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_SCONN_LEN)
endif()

check_struct_has_member("struct sockaddr_in" "sin_len" "sys/types.h;netinet/in.h" HAVE_SIN_LEN)
if(HAVE_SIN_LEN)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_SIN_LEN)
endif()

check_struct_has_member("struct sockaddr_in6" "sin6_len" "sys/types.h;netinet/in.h" HAVE_SIN6_LEN)
if(HAVE_SIN6_LEN)
	list(APPEND USRSCTP_DEFINITIONS -DHAVE_SIN6_LEN)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	list(APPEND USRSCTP_DEFINITIONS -D_GNU_SOURCE)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
	list(APPEND USRSCTP_DEFINITIONS -D__Userspace_os_Linux)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	list(APPEND USRSCTP_DEFINITIONS -U__FreeBSD__)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	list(APPEND USRSCTP_DEFINITIONS -U__APPLE__)
	list(APPEND USRSCTP_DEFINITIONS -D__APPLE_USE_RFC_2292)
endif()

if(IOS)
    list(APPEND USRSCTP_DEFINITIONS -D__Userspace_os_IOS)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "DragonFly")
	list(APPEND USRSCTP_DEFINITIONS -U__DragonFly__)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
	list(APPEND USRSCTP_DEFINITIONS -U__NetBSD__)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
	list(APPEND USRSCTP_DEFINITIONS -U__OpenBSD__)
endif()

option(INVARIANTS "Add runtime checks" 0)
if(INVARIANTS)
	list(APPEND USRSCTP_DEFINITIONS -DINVARIANTS)
endif()

option(SCTP_DEBUG "Provide debug information" 1)
if(SCTP_DEBUG)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_DEBUG)
endif()

option(INET "Support IPv4 " 1)
if(INET)
	list(APPEND USRSCTP_DEFINITIONS -DINET)
endif()

option(INET6 "Support IPv6 " 1)
if(INET6)
	list(APPEND USRSCTP_DEFINITIONS -DINET6)
endif()

option(SCTP_SIMPLE_ALLOCATOR " " 1)
if(SCTP_SIMPLE_ALLOCATOR)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_SIMPLE_ALLOCATOR)
endif()

option(SCTP_PROCESS_LEVEL_LOCKS " " 1)
if(SCTP_PROCESS_LEVEL_LOCKS)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_PROCESS_LEVEL_LOCKS)
endif()

option(SCTP_WITH_NO_CSUM "Disable SCTP checksum" 0)
if(SCTP_WITH_NO_CSUM)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_WITH_NO_CSUM)
endif()

option(SCTP_MBUF_LOGGING " " 0)
if(SCTP_MBUF_LOGGING)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_MBUF_LOGGING)
endif()

option(SCTP_PACKET_LOGGING " " 0)
if(SCTP_PACKET_LOGGING)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_PACKET_LOGGING)
endif()

option(SCTP_SO_LOCK_TESTING " " 0)
if(SCTP_SO_LOCK_TESTING)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_SO_LOCK_TESTING)
endif()

option(SCTP_EMBEDDED_V6_SCOPE " " 0)
if(SCTP_EMBEDDED_V6_SCOPE)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_EMBEDDED_V6_SCOPE)
endif()

option(SCTP_KAME " " 0)
if(SCTP_KAME)
	list(APPEND USRSCTP_DEFINITIONS -DSCTP_KAME)
endif()

set(USRSCTP_CONFIG "usrsctp-config.h")

set(CFG "${CFG} #ifndef USRSCTP_CONFIG_H\n")
set(CFG "${CFG} #define USRSCTP_CONFIG_H\n\n")

foreach(USRSCTP_DEFINITION ${USRSCTP_DEFINITIONS})
	if(${USRSCTP_DEFINITION} MATCHES "^-D(.*)")
		set(USRSCTP_DEF ${CMAKE_MATCH_1})
		set(CFG "${CFG} #ifndef ${USRSCTP_DEF}\n")
		set(CFG "${CFG} #define ${USRSCTP_DEF}\n")
		set(CFG "${CFG} #endif\n\n")
	elseif(${USRSCTP_DEFINITION} MATCHES "^-U(.*)")
		set(USRSCTP_UNDEF ${CMAKE_MATCH_1})
		set(CFG "${CFG} #ifdef ${USRSCTP_UNDEF}\n")
		set(CFG "${CFG} #undef ${USRSCTP_UNDEF}\n")
		set(CFG "${CFG} #endif\n\n")
	endif()
endforeach()

set(CFG "${CFG} \n#endif /* USRSCTP_CONFIG_H */\n")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${USRSCTP_CONFIG}" ${CFG})

add_definitions(${USRSCTP_DEFINITIONS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
	"${CMAKE_CURRENT_SOURCE_DIR}/inet"
	"${CMAKE_CURRENT_SOURCE_DIR}/inet6")

list(APPEND usrsctp_root_HEADERS
	user_atomic.h
	user_inpcb.h
	user_ip_icmp.h
	user_mbuf.h
	user_recv_thread.h
	user_socketvar.h
	usrsctp.h
	user_environment.h
	user_ip6_var.h
	user_malloc.h
	user_queue.h
	user_route.h
	user_uma.h)

list(APPEND usrsctp_netinet_HEADERS
	netinet/sctp_asconf.h
	netinet/sctp_constants.h
	netinet/sctp_indata.h
	netinet/sctp_os_userspace.h
	netinet/sctp_process_lock.h
	netinet/sctp_timer.h
	netinet/sctp_auth.h
	netinet/sctp_crc32.h
	netinet/sctp_input.h
	netinet/sctp_output.h
	netinet/sctp_sha1.h
	netinet/sctp_uio.h
	netinet/sctp_bsd_addr.h
	netinet/sctp.h
	netinet/sctp_lock_userspace.h
	netinet/sctp_pcb.h
	netinet/sctp_structs.h
	netinet/sctputil.h
	netinet/sctp_callout.h
	netinet/sctp_header.h
	netinet/sctp_os.h
	netinet/sctp_peeloff.h
	netinet/sctp_sysctl.h
	netinet/sctp_var.h)

list(APPEND usrsctp_netinet6_HEADERS
	netinet6/sctp6_var.h)

list(APPEND usrsctp_SOURCES
	netinet6/sctp6_usrreq.c
	netinet/sctp_callout.c
	netinet/sctp_input.c
	netinet/sctp_sha1.c
	netinet/sctp_userspace.c
	user_mbuf.c
	netinet/sctp_asconf.c
	netinet/sctp_cc_functions.c
	netinet/sctp_output.c
	netinet/sctp_ss_functions.c
	netinet/sctp_usrreq.c
	user_recv_thread.c
	netinet/sctp_auth.c
	netinet/sctp_crc32.c
	netinet/sctp_pcb.c
	netinet/sctp_sysctl.c
	netinet/sctputil.c
	user_socket.c
	netinet/sctp_bsd_addr.c
	netinet/sctp_indata.c
	netinet/sctp_peeloff.c
	netinet/sctp_timer.c
	user_environment.c)

if(ANDROID)
	list(APPEND usrsctp_root_HEADERS android_ifaddrs.h)
	list(APPEND usrsctp_SOURCES android_ifaddrs.c)
endif()

if(IOS)
    list(APPEND usrsctp_root_HEADERS ios_ip6.h)
    list(APPEND usrsctp_root_HEADERS ios_route.h)
    list(APPEND usrsctp_root_HEADERS ios_udp.h)
    list(APPEND usrsctp_root_HEADERS ios_icmp6.h)
endif()

list(APPEND usrsctp_HEADERS
	${usrsctp_root_HEADERS}
	${usrsctp_netinet_HEADERS}
	${usrsctp_netinet6_HEADERS})

add_library(usrsctp STATIC ${usrsctp_SOURCES} ${usrsctp_HEADERS})

if(WIN32)
	target_link_libraries(usrsctp ws2_32)
endif()

set_target_properties(usrsctp PROPERTIES OUTPUT_NAME "usrsctp")

if(IOS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
    set_target_properties(usrsctp PROPERTIES XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "${IOS_DEPLOYMENT_TARGET}")
endif()

set_property(TARGET usrsctp PROPERTY FOLDER "external")

if("x${CMAKE_C_COMPILER_ID}" STREQUAL "xClang" OR "x${CMAKE_C_COMPILER_ID}" STREQUAL "xGNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall")
endif()

if("x${CMAKE_C_COMPILER_ID}" STREQUAL "xGNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-redundant-decls")
endif()

if("x${CMAKE_C_COMPILER_ID}" STREQUAL "xMSVC")
	if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
		STRING(REGEX REPLACE "/W[0-4]" "/W3" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3")
	endif()
endif()

if("x${CMAKE_C_COMPILER_ID}" STREQUAL "xMSVC90" OR "x${CMAKE_C_COMPILER_ID}" STREQUAL "xMSVC10")
	SET_SOURCE_FILES_PROPERTIES(${usrsctp_SOURCES} PROPERTIES LANGUAGE C)
endif()

