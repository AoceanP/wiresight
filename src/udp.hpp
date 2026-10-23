#pragma once

#include "bytes.hpp"

#include <optional>

namespace wiresight
{

/**
 * WHAT:   A UDP header.
 * WHY:    UDP carries DNS, DHCP, video calls and games: small, fast
 *         messages with no handshake.
 */
struct UdpDatagram
{
	/** WHAT: port on the sender. */
	std::uint16_t sourcePort = 0;
	/** WHAT: port on the receiver (53 for DNS). */
	std::uint16_t destinationPort = 0;
	/** WHAT: header plus data, as the sender stated it. */
	std::uint16_t length = 0;
	/** WHAT: the data, cut to length. */
	Bytes payload;
	/** WHAT: length promised more bytes than were captured. */
	bool truncated = false;
};

/**
 * WHAT:   Decodes a UDP header.
 * WHY:    The length field decides where the data ends, so padding after it
 *         is never treated as data.
 * PRE:    data starts at the UDP header
 * RETURN: the datagram, or nothing if it is shorter than 8 bytes or its
 *         length field is below 8
 *
 * @param data the transport bytes from the IP layer
 * @return the decoded datagram, or std::nullopt
 */
std::optional<UdpDatagram> parseUdp(Bytes data);

} // namespace wiresight
