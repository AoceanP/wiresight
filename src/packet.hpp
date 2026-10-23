#pragma once

#include "arp.hpp"
#include "bytes.hpp"
#include "dns.hpp"
#include "ethernet.hpp"
#include "icmp.hpp"
#include "ipv4.hpp"
#include "ipv6.hpp"
#include "tcp.hpp"
#include "udp.hpp"

#include <optional>
#include <string>
#include <vector>

namespace wiresight
{

/**
 * WHAT:   What the first header of a captured frame is.
 * WHY:    A network card gives Ethernet frames, but the loopback adapter
 *         (127.0.0.1 traffic) gives a 4-byte "null" header instead, and
 *         some captures start straight at the IP header.
 */
enum class LinkType
{
	/** WHAT: Ethernet II, wired or Wi-Fi as Windows presents it (DLT 1). */
	Ethernet,
	/** WHAT: BSD loopback: a 4-byte address family, then IP (DLT 0). */
	Null,
	/** WHAT: the frame starts at the IP header (DLT 12, 14, 101). */
	Raw,
	/** WHAT: anything else; only lengths are shown. */
	Unknown
};

/**
 * WHAT:   Maps a libpcap data link type number to a LinkType.
 * WHY:    pcap_datalink() reports the capture's first header as a number.
 * RETURN: the matching LinkType, or LinkType::Unknown
 *
 * @param dlt the number from pcap_datalink()
 * @return the link type
 */
LinkType linkTypeFromDlt(int dlt);

/**
 * WHAT:   Every layer that could be decoded from one captured frame.
 * WHY:    Each layer is optional, so a frame that stops early (ARP has no
 *         IP; a fragment has no TCP) still shows what it does contain.
 *         Payload spans point into the captured buffer, so it must stay
 *         alive while this is used.
 */
struct DecodedPacket
{
	/** WHAT: bytes actually captured (can be less than sent; see the snapshot length). */
	std::size_t capturedLength = 0;
	/** WHAT: bytes the frame had on the wire. */
	std::size_t originalLength = 0;
	/** WHAT: link layer, when the capture is Ethernet. */
	std::optional<EthernetFrame> ethernet;
	/** WHAT: ARP, when the frame carries it. */
	std::optional<ArpPacket> arp;
	/** WHAT: IPv4 header, when present. */
	std::optional<Ipv4Packet> ipv4;
	/** WHAT: IPv6 header, when present. */
	std::optional<Ipv6Packet> ipv6;
	/** WHAT: TCP header, when present and not inside a later fragment. */
	std::optional<TcpSegment> tcp;
	/** WHAT: UDP header, when present. */
	std::optional<UdpDatagram> udp;
	/** WHAT: ICMP or ICMPv6 message, when present. */
	std::optional<IcmpMessage> icmp;
	/** WHAT: DNS message, when UDP uses port 53 or 5353 (mDNS). */
	std::optional<DnsMessage> dns;
	/** WHAT: anything unusual: cut short, bad checksum, fragment, malformed. */
	std::vector<std::string> notes;
};

/**
 * WHAT:   Decodes a frame layer by layer: link, network, transport, DNS.
 * WHY:    Every decoder refuses data it cannot trust, so a short or hostile
 *         frame becomes notes, never a crash or an out-of-bounds read.
 * PRE:    data stays valid while the result is used
 * RETURN: the layers found, plus notes about anything unusual
 *
 * @param data           the captured bytes
 * @param link           the capture's first header type
 * @param originalLength the frame's size on the wire (from the pcap header)
 * @return the decoded packet
 */
DecodedPacket decode(Bytes data, LinkType link, std::size_t originalLength);

} // namespace wiresight
