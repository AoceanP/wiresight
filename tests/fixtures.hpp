#pragma once

#include "test.hpp"

#include <cstdint>
#include <vector>

/**
 * WHAT:   Real packets, written byte by byte, shared by the test files.
 * WHY:    Each one is a packet you would actually see on a home network,
 *         so the tests check real-world decoding, not made-up shapes.
 */
namespace fixtures
{

/**
 * WHAT:   A TCP SYN from 192.168.1.5:51256 to 93.184.216.34:443, with an MSS option.
 * WHY:    The first packet of every HTTPS connection; 58 bytes on Ethernet.
 * RETURN: the Ethernet frame
 *
 * @return the frame bytes
 */
inline std::vector<std::uint8_t> tcpSyn()
{
	auto frame = test::hex(
		"00 11 22 33 44 55  66 77 88 99 aa bb  08 00"                                   // Ethernet
		"45 00 00 2c  00 01 40 00  40 06 00 00  c0 a8 01 05  5d b8 d8 22"               // IPv4, DF, TTL 64
		"c8 38 01 bb  00 00 00 64  00 00 00 00  60 02 fa f0  00 00 00 00  02 04 05 b4"); // TCP SYN + MSS 1460
	test::fixIpv4Checksum(frame, 14);
	return frame;
}

/**
 * WHAT:   A DNS query for the A record of example.com, to 1.1.1.1.
 * WHY:    The most common UDP packet on any network.
 * RETURN: the Ethernet frame
 *
 * @return the frame bytes
 */
inline std::vector<std::uint8_t> dnsQuery()
{
	auto frame = test::hex(
		"00 11 22 33 44 55  66 77 88 99 aa bb  08 00"
		"45 00 00 39  00 02 00 00  40 11 00 00  c0 a8 01 05  01 01 01 01"
		"d4 31 00 35  00 25 00 00"                              // UDP 54321 -> 53, length 37
		"1a 2b 01 00  00 01 00 00  00 00 00 00"                 // DNS header: id, RD, 1 question
		"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00  00 01 00 01"); // example.com, A, IN
	test::fixIpv4Checksum(frame, 14);
	return frame;
}

/**
 * WHAT:   The DNS response to dnsQuery: example.com A 93.184.216.34.
 * WHY:    The answer's name is a compression pointer (c0 0c) to the
 *         question, as in almost every real response.
 * RETURN: the DNS message only (no Ethernet/IP/UDP)
 *
 * @return the message bytes
 */
inline std::vector<std::uint8_t> dnsResponse()
{
	return test::hex(
		"1a 2b 81 80  00 01 00 01  00 00 00 00"
		"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00  00 01 00 01"
		"c0 0c  00 01 00 01  00 00 0e 10  00 04  5d b8 d8 22"); // pointer to offset 12, A, TTL 3600
}

/**
 * WHAT:   An ARP request: who has 192.168.1.1? tell 192.168.1.5.
 * WHY:    What every PC sends to find its router's MAC address.
 * RETURN: the Ethernet frame
 *
 * @return the frame bytes
 */
inline std::vector<std::uint8_t> arpRequest()
{
	return test::hex(
		"ff ff ff ff ff ff  66 77 88 99 aa bb  08 06"
		"00 01 08 00 06 04 00 01  66 77 88 99 aa bb  c0 a8 01 05  00 00 00 00 00 00  c0 a8 01 01");
}

/**
 * WHAT:   An IPv6 ping from fe80::1 to ff02::1 behind a hop-by-hop header.
 * WHY:    Checks the extension header walk; starts at the IP header (raw link type).
 * RETURN: the IPv6 packet
 *
 * @return the packet bytes
 */
inline std::vector<std::uint8_t> ipv6PingWithHopByHop()
{
	return test::hex(
		"60 00 00 00  00 10 00 40"                                 // payload 16, next header 0 (hop-by-hop), hop limit 64
		"fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 01"          // fe80::1
		"ff 02 00 00 00 00 00 00 00 00 00 00 00 00 00 01"          // ff02::1
		"3a 00 01 04 00 00 00 00"                                  // hop-by-hop: next 58 (ICMPv6), PadN
		"80 00 00 00  00 01 00 02");                               // echo request id 1 seq 2
}

} // namespace fixtures
