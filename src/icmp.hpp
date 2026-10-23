#pragma once

#include "bytes.hpp"

#include <optional>
#include <string>

namespace wiresight
{

/**
 * WHAT:   An ICMP or ICMPv6 message: ping, unreachable, time exceeded, and
 *         for IPv6 also neighbour discovery.
 * WHY:    ICMP explains why traffic fails, e.g. "port unreachable" is how a
 *         closed UDP port answers, and traceroute is built on "time exceeded".
 */
struct IcmpMessage
{
	/** WHAT: true for ICMPv6, whose type numbers differ from ICMP. */
	bool version6 = false;
	/** WHAT: message type, e.g. 8 echo request (ICMP) or 128 (ICMPv6). */
	std::uint8_t type = 0;
	/** WHAT: detail for the type, e.g. 3 "port unreachable". */
	std::uint8_t code = 0;
	/** WHAT: echo identifier, for ping messages only. */
	std::optional<std::uint16_t> identifier;
	/** WHAT: echo sequence number, for ping messages only. */
	std::optional<std::uint16_t> sequence;
};

/**
 * WHAT:   Decodes an ICMP or ICMPv6 header.
 * WHY:    One function for both, since the first 4 bytes have the same layout.
 * PRE:    data starts at the ICMP header
 * RETURN: the message, or nothing if it is shorter than 4 bytes
 *
 * @param data     the transport bytes from the IP layer
 * @param version6 true when the IP layer was IPv6 (protocol 58)
 * @return the decoded message, or std::nullopt
 */
std::optional<IcmpMessage> parseIcmp(Bytes data, bool version6);

/**
 * WHAT:   Describes a message in words, e.g. "destination unreachable (port)".
 * WHY:    Type and code numbers mean nothing to most readers.
 * RETURN: the description, or "type T code C" for unknown messages
 *
 * @param message the decoded message
 * @return the readable description
 */
std::string describeIcmp(const IcmpMessage& message);

} // namespace wiresight
