#pragma once

#include "bytes.hpp"

#include <optional>

namespace wiresight
{

/** WHAT: ARP operation "who has this IP?". */
inline constexpr std::uint16_t ARP_REQUEST = 1;
/** WHAT: ARP operation "this IP is at this MAC". */
inline constexpr std::uint16_t ARP_REPLY = 2;

/**
 * WHAT:   An ARP packet for IPv4 over Ethernet.
 * WHY:    ARP is how a PC finds the MAC address of its router and
 *         neighbours; it is also what ARP spoofing attacks forge, so seeing
 *         it matters for both networking and security.
 */
struct ArpPacket
{
	/** WHAT: ARP_REQUEST, ARP_REPLY or another operation number. */
	std::uint16_t operation = 0;
	/** WHAT: MAC address of the machine sending the ARP packet. */
	MacAddress senderMac{};
	/** WHAT: IPv4 address of the machine sending the ARP packet. */
	Ipv4Address senderIp{};
	/** WHAT: MAC address being asked about (all zeros in a request). */
	MacAddress targetMac{};
	/** WHAT: IPv4 address being asked about. */
	Ipv4Address targetIp{};
};

/**
 * WHAT:   Decodes an ARP packet.
 * WHY:    Only the Ethernet + IPv4 form exists on real networks, so other
 *         hardware or protocol types are refused instead of misread.
 * PRE:    data starts at the ARP header (the Ethernet payload)
 * RETURN: the packet, or nothing if it is short or not Ethernet/IPv4 ARP
 *
 * @param data the bytes after the Ethernet header
 * @return the decoded packet, or std::nullopt
 */
std::optional<ArpPacket> parseArp(Bytes data);

} // namespace wiresight
