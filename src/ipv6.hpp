#pragma once

#include "bytes.hpp"

#include <optional>
#include <vector>

namespace wiresight
{

/**
 * WHAT:   An IPv6 header, with the extension headers between it and the
 *         transport layer already walked.
 * WHY:    Home networks use IPv6 constantly (DNS, neighbour discovery), and
 *         the real protocol can hide behind hop-by-hop, routing,
 *         destination or fragment headers.
 */
struct Ipv6Packet
{
	/** WHAT: priority bits, like IPv4's type of service. */
	std::uint8_t trafficClass = 0;
	/** WHAT: 20-bit label grouping packets of one flow. */
	std::uint32_t flowLabel = 0;
	/** WHAT: bytes after the 40-byte fixed header. */
	std::uint16_t payloadLength = 0;
	/** WHAT: the header type right after the fixed header. */
	std::uint8_t nextHeader = 0;
	/** WHAT: hops left, IPv6's name for TTL. */
	std::uint8_t hopLimit = 0;
	/** WHAT: sender address. */
	Ipv6Address source{};
	/** WHAT: receiver address. */
	Ipv6Address destination{};
	/** WHAT: the extension header types that were skipped, in order. */
	std::vector<std::uint8_t> extensionHeaders;
	/** WHAT: the transport protocol after all extension headers (6, 17, 58...). */
	std::uint8_t upperProtocol = 0;
	/** WHAT: the transport data. */
	Bytes upperPayload;
	/** WHAT: a fragment header was present. */
	bool fragmented = false;
	/** WHAT: where this fragment's data belongs, in bytes (0 for the first fragment). */
	std::size_t fragmentOffset = 0;
	/** WHAT: payloadLength promised more bytes than were captured. */
	bool truncated = false;
};

/**
 * WHAT:   Decodes an IPv6 header and skips its extension headers.
 * WHY:    At most 8 extension headers are walked and each length is
 *         checked, so a crafted chain cannot loop or read past the data.
 * PRE:    data starts at the IPv6 header
 * RETURN: the header, or nothing if it is short or not version 6
 *
 * @param data the bytes of the IP packet
 * @return the decoded header, or std::nullopt
 */
std::optional<Ipv6Packet> parseIpv6(Bytes data);

} // namespace wiresight
