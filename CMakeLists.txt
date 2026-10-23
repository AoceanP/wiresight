cmake_minimum_required(VERSION 3.20)
project(wiresight VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
	add_compile_options(/W4 /permissive-)
else()
	add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
endif()

# Decoders and formatting are plain C++ with no capture library, so they build
# and run their tests on any machine, even without Npcap or libpcap.
add_library(wiresight_core STATIC
	src/bytes.cpp
	src/ethernet.cpp
	src/arp.cpp
	src/ipv4.cpp
	src/ipv6.cpp
	src/tcp.cpp
	src/udp.cpp
	src/icmp.cpp
	src/dns.cpp
	src/packet.cpp
	src/format.cpp
)
target_include_directories(wiresight_core PUBLIC src)

# MinGW programs otherwise need libstdc++ and libgcc DLLs from the compiler folder at run time
if(MINGW)
	set(STATIC_RUNTIME -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_executable(wiresight_tests
	tests/test_main.cpp
	tests/test_link.cpp
	tests/test_network.cpp
	tests/test_transport.cpp
	tests/test_dns.cpp
	tests/test_format.cpp
	tests/test_edge_cases.cpp
)
target_link_libraries(wiresight_tests PRIVATE wiresight_core)
target_link_options(wiresight_tests PRIVATE ${STATIC_RUNTIME})
add_test(NAME wiresight_tests COMMAND wiresight_tests)

# The capture program needs the pcap headers. On Windows they come from the
# Npcap SDK; wpcap.dll itself is loaded at run time, so nothing is linked.
set(HAVE_PCAP OFF)
if(WIN32)
	set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK}" CACHE PATH "Npcap SDK folder (the one containing Include/pcap.h)")
	if(EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
		set(HAVE_PCAP ON)
		set(PCAP_INCLUDE "${NPCAP_SDK_DIR}/Include")
	else()
		message(WARNING "Npcap SDK not found, so only the tests are built. Download it from "
			"https://npcap.com/#download and pass -DNPCAP_SDK_DIR=<folder> or set the NPCAP_SDK environment variable.")
	endif()
else()
	find_path(PCAP_INCLUDE pcap.h)
	find_library(PCAP_LIBRARY pcap)
	if(PCAP_INCLUDE AND PCAP_LIBRARY)
		set(HAVE_PCAP ON)
	else()
		message(WARNING "libpcap not found, so only the tests are built. Install libpcap-dev (Debian/Ubuntu) "
			"or libpcap-devel (Fedora).")
	endif()
endif()

if(HAVE_PCAP)
	add_executable(wiresight src/capture.cpp src/main.cpp)
	target_include_directories(wiresight PRIVATE "${PCAP_INCLUDE}")
	target_link_libraries(wiresight PRIVATE wiresight_core)
	target_link_options(wiresight PRIVATE ${STATIC_RUNTIME})
	if(NOT WIN32)
		target_link_libraries(wiresight PRIVATE "${PCAP_LIBRARY}")
	endif()
endif()
