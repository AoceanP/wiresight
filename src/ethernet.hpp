#pragma once

#include "bytes.hpp"

#include <optional>

namespace wiresight
{

/** WHAT: EtherType of an IPv4 packet. */
inline constexpr std::uint16_t ETHERTYPE_IPV4 = 0x0800;
/** WHAT: EtherType of an ARP packet. */
inline constexpr std::uint16_t ETHERTYPE_ARP = 0x0806;
/** WHAT: EtherType that announces an 802.1Q VLAN tag. */
inline constexpr std::uint16_t ETHERTYPE_VLAN = 0x8100;
/** WHAT: EtherType of an IPv6 packet. */
inline constexpr std::uint16_t ETHERTYPE_IPV6 = 0x86DD;

/**
 * WHAT:   The Ethernet II header: who sent the frame on the local network,
 *         who it is for, and what protocol is inside.
 * WHY:    It is the outermost layer on a wired or Wi-Fi capture, so every
 *         other decoder starts from its payload.
 */
struct EthernetFrame
{
	/** WHAT: the MAC address the frame is sent to. */
	MacAddress destination{};
	/** WHAT: the MAC address that sent the frame. */
	MacAddress source{};
	/** WHAT: the protocol inside (0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP), or an 802.3 length. */
	std::uint16_t etherType = 0;
	/** WHAT: the VLAN number when the frame carries an 802.1Q tag. */
	std::optional<std::uint16_t> vlanId;
	/** WHAT: 14 bytes, or 18 with a VLAN tag. */
	std::size_t headerLength = 0;
	/** WHAT: everything after the header. */
	Bytes payload;

	/**
	 * WHAT:   Tells an old 802.3 frame from an Ethernet II frame.
	 * WHY:    Values below 0x0600 in the type field are a length, not a
	 *         protocol; switches still send these (spanning tree, LLC).
	 * RETURN: true for an 802.3 length field
	 *
	 * @return whether etherType is really a length
	 */
	bool isLengthField() const
	{
		return etherType < 0x0600;
	}
};

/**
 * WHAT:   Decodes an Ethernet II header, including one 802.1Q VLAN tag.
 * WHY:    Office networks tag frames with VLANs; without handling the tag,
 *         every packet on a trunk port would look like an unknown protocol.
 * PRE:    frame is the whole captured frame
 * RETURN: the header, or nothing if the frame is too short
 *
 * @param frame the captured bytes
 * @return the decoded header, or std::nullopt if it is incomplete
 */
std::optional<EthernetFrame> parseEthernet(Bytes frame);

} // namespace wiresight
