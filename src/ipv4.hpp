#pragma once

#include "bytes.hpp"

#include <optional>

namespace wiresight
{

/** WHAT: IP protocol number of ICMP (ping). */
inline constexpr std::uint8_t PROTOCOL_ICMP = 1;
/** WHAT: IP protocol number of TCP. */
inline constexpr std::uint8_t PROTOCOL_TCP = 6;
/** WHAT: IP protocol number of UDP. */
inline constexpr std::uint8_t PROTOCOL_UDP = 17;
/** WHAT: IP protocol number of ICMPv6. */
inline constexpr std::uint8_t PROTOCOL_ICMPV6 = 58;

/**
 * WHAT:   An IPv4 header: where the packet comes from, where it goes, and
 *         what transport protocol it carries.
 * WHY:    IP is the layer that crosses the internet, so its addresses are
 *         the ones that identify both ends of a conversation.
 */
struct Ipv4Packet
{
	/** WHAT: header size in bytes, 20 to 60 (more than 20 means options are present). */
	std::size_t headerLength = 0;
	/** WHAT: header plus data, as the sender stated it. */
	std::uint16_t totalLength = 0;
	/** WHAT: number shared by all fragments of one original packet. */
	std::uint16_t identification = 0;
	/** WHAT: the sender asked routers not to fragment this packet. */
	bool dontFragment = false;
	/** WHAT: more fragments of this packet follow. */
	bool moreFragments = false;
	/** WHAT: where this fragment's data belongs in the original packet, in bytes. */
	std::size_t fragmentOffset = 0;
	/** WHAT: hops left before a router drops the packet. */
	std::uint8_t ttl = 0;
	/** WHAT: transport protocol inside (6 TCP, 17 UDP, 1 ICMP). */
	std::uint8_t protocol = 0;
	/** WHAT: header checksum as sent. */
	std::uint16_t checksum = 0;
	/** WHAT: whether the checksum matches the header. */
	bool checksumValid = false;
	/** WHAT: sender address. */
	Ipv4Address source{};
	/** WHAT: receiver address. */
	Ipv4Address destination{};
	/** WHAT: the transport data, cut to totalLength. */
	Bytes payload;
	/** WHAT: totalLength promised more bytes than were captured. */
	bool truncated = false;
};

/**
 * WHAT:   Computes the Internet checksum (RFC 1071) of some bytes.
 * WHY:    Used to verify IPv4 headers: summing a header that includes its
 *         own correct checksum gives 0.
 * RETURN: the ones' complement of the ones' complement sum of 16-bit words
 *
 * @param data the bytes to sum; an odd last byte is padded with zero
 * @return the checksum value
 */
std::uint16_t internetChecksum(Bytes data);

/**
 * WHAT:   Decodes an IPv4 header.
 * WHY:    Every length field is checked, because a captured packet can be
 *         cut short or deliberately malformed.
 * PRE:    data starts at the IPv4 header
 * RETURN: the header, or nothing if it is not valid IPv4
 *
 * @param data the bytes of the IP packet
 * @return the decoded header, or std::nullopt if the version, header
 *         length or total length is impossible
 */
std::optional<Ipv4Packet> parseIpv4(Bytes data);

} // namespace wiresight
