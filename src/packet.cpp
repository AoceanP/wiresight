#include "packet.hpp"

#include <format>

namespace wiresight
{

namespace
{

/**
 * WHAT:   Tells whether a UDP port carries DNS.
 * WHY:    53 is normal DNS; 5353 is multicast DNS, which printers, phones
 *         and smart TVs use to announce themselves on a home network.
 * RETURN: true for 53 or 5353
 *
 * @param port the UDP port
 * @return whether DNS should be decoded
 */
bool isDnsPort(std::uint16_t port)
{
	return port == 53 || port == 5353;
}

/**
 * WHAT:   Decodes the transport layer (and DNS on top of UDP).
 * WHY:    IPv4 and IPv6 hand over the same protocol numbers, so one
 *         function serves both.
 * POST:   fills packet.tcp, udp, icmp or dns, or adds a note
 *
 * @param packet   the packet being filled in
 * @param protocol the IP protocol number
 * @param payload  the bytes after the IP header(s)
 */
void decodeTransport(DecodedPacket& packet, std::uint8_t protocol, Bytes payload)
{
	switch (protocol)
	{
	case PROTOCOL_TCP:
		packet.tcp = parseTcp(payload);
		if (!packet.tcp)
		{
			packet.notes.emplace_back("TCP header incomplete");
		}
		break;

	case PROTOCOL_UDP:
		packet.udp = parseUdp(payload);
		if (!packet.udp)
		{
			packet.notes.emplace_back("UDP header incomplete");
			break;
		}
		if (isDnsPort(packet.udp->sourcePort) || isDnsPort(packet.udp->destinationPort))
		{
			packet.dns = parseDns(packet.udp->payload);
			if (packet.dns && packet.dns->malformed)
			{
				packet.notes.emplace_back("DNS message malformed or cut short");
			}
		}
		break;

	case PROTOCOL_ICMP:
	case PROTOCOL_ICMPV6:
		packet.icmp = parseIcmp(payload, protocol == PROTOCOL_ICMPV6);
		if (!packet.icmp)
		{
			packet.notes.emplace_back("ICMP header incomplete");
		}
		break;

	default:
		break;
	}
}

/**
 * WHAT:   Decodes an IP packet, choosing IPv4 or IPv6 from its first nibble.
 * WHY:    The version is in the packet itself, so this also works for the
 *         loopback and raw link types that have no EtherType.
 * POST:   fills packet.ipv4 or ipv6 and the layers above, or adds a note
 *
 * @param packet the packet being filled in
 * @param data   the bytes starting at the IP header
 */
void decodeIp(DecodedPacket& packet, Bytes data)
{
	if (data.empty())
	{
		packet.notes.emplace_back("no IP header");
		return;
	}

	switch (data[0] >> 4)
	{
	case 4:
		packet.ipv4 = parseIpv4(data);
		if (!packet.ipv4)
		{
			packet.notes.emplace_back("IPv4 header incomplete or invalid");
			return;
		}
		if (!packet.ipv4->checksumValid)
		{
			packet.notes.emplace_back("IPv4 checksum mismatch (normal for packets this PC sends: the network card fills it in)");
		}
		// only the first fragment holds the TCP/UDP header
		if (packet.ipv4->fragmentOffset != 0)
		{
			packet.notes.push_back(std::format("IPv4 fragment at offset {}", packet.ipv4->fragmentOffset));
			return;
		}
		decodeTransport(packet, packet.ipv4->protocol, packet.ipv4->payload);
		return;

	case 6:
		packet.ipv6 = parseIpv6(data);
		if (!packet.ipv6)
		{
			packet.notes.emplace_back("IPv6 header incomplete or invalid");
			return;
		}
		if (packet.ipv6->fragmented && packet.ipv6->fragmentOffset != 0)
		{
			packet.notes.push_back(std::format("IPv6 fragment at offset {}", packet.ipv6->fragmentOffset));
			return;
		}
		decodeTransport(packet, packet.ipv6->upperProtocol, packet.ipv6->upperPayload);
		return;

	default:
		packet.notes.push_back(std::format("unknown IP version {}", data[0] >> 4));
		return;
	}
}

} // namespace

LinkType linkTypeFromDlt(int dlt)
{
	switch (dlt)
	{
	case 1: return LinkType::Ethernet;
	case 0: return LinkType::Null;
	case 12:
	case 14:
	case 101: return LinkType::Raw;
	default: return LinkType::Unknown;
	}
}

DecodedPacket decode(Bytes data, LinkType link, std::size_t originalLength)
{
	DecodedPacket packet;
	packet.capturedLength = data.size();
	packet.originalLength = std::max(originalLength, data.size());
	if (packet.capturedLength < packet.originalLength)
	{
		packet.notes.push_back(std::format("only {} of {} bytes captured", packet.capturedLength, packet.originalLength));
	}

	switch (link)
	{
	case LinkType::Ethernet:
		packet.ethernet = parseEthernet(data);
		if (!packet.ethernet)
		{
			packet.notes.emplace_back("Ethernet header incomplete");
			break;
		}
		if (packet.ethernet->etherType == ETHERTYPE_IPV4 || packet.ethernet->etherType == ETHERTYPE_IPV6)
		{
			decodeIp(packet, packet.ethernet->payload);
		}
		else if (packet.ethernet->etherType == ETHERTYPE_ARP)
		{
			packet.arp = parseArp(packet.ethernet->payload);
			if (!packet.arp)
			{
				packet.notes.emplace_back("ARP packet incomplete or not Ethernet/IPv4");
			}
		}
		break;

	case LinkType::Null:
		// the 4-byte address family is in the capturing machine's byte order; the IP
		// version nibble after it is enough to tell IPv4 from IPv6
		if (data.size() < 4)
		{
			packet.notes.emplace_back("loopback header incomplete");
			break;
		}
		decodeIp(packet, data.subspan(4));
		break;

	case LinkType::Raw:
		decodeIp(packet, data);
		break;

	case LinkType::Unknown:
		packet.notes.emplace_back("link type not supported; only the length is shown");
		break;
	}
	return packet;
}

} // namespace wiresight
