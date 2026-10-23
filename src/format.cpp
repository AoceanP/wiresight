#include "format.hpp"

#include <ctime>
#include <format>

namespace wiresight
{

namespace
{

/** WHAT: how many DNS answers a summary line lists before "(+N more)". */
constexpr std::size_t ANSWERS_SHOWN = 3;

/**
 * WHAT:   Formats one end of a conversation, e.g. "10.0.0.1:443" or "[fe80::1]:53".
 * WHY:    IPv6 addresses contain colons, so they need brackets before a port.
 * RETURN: the address, with ":port" when a port is given
 *
 * @param packet the packet holding the IP layer
 * @param source true for the sender, false for the receiver
 * @param port   the transport port, if any
 * @return the formatted endpoint
 */
std::string endpoint(const DecodedPacket& packet, bool source, std::optional<std::uint16_t> port)
{
	std::string address;
	if (packet.ipv4)
	{
		address = toString(source ? packet.ipv4->source : packet.ipv4->destination);
	}
	else if (packet.ipv6)
	{
		address = toString(source ? packet.ipv6->source : packet.ipv6->destination);
		if (port)
		{
			address = "[" + address + "]";
		}
	}
	return port ? std::format("{}:{}", address, *port) : address;
}

/**
 * WHAT:   Describes a DNS message, e.g. "query 0x1a2b A example.com".
 * WHY:    Shows the question, and for responses the result and answers,
 *         which is what people look at DNS traffic for.
 * RETURN: the description
 *
 * @param dns the decoded DNS message
 * @return the readable description
 */
std::string describeDns(const DnsMessage& dns)
{
	std::string question = "(no question)";
	if (!dns.questions.empty())
	{
		question = dnsTypeName(dns.questions.front().type) + " " + dns.questions.front().name;
	}

	if (!dns.isResponse)
	{
		return std::format("query 0x{:04x} {}", dns.id, question);
	}

	std::string text = std::format("response 0x{:04x} {} {}", dns.id, dnsRcodeName(dns.rcode), question);
	for (std::size_t i = 0; i < dns.answers.size() && i < ANSWERS_SHOWN; ++i)
	{
		text += (i == 0 ? " -> " : ", ") + dns.answers[i].data;
	}
	if (dns.answerCount > ANSWERS_SHOWN)
	{
		text += std::format(" (+{} more)", dns.answerCount - ANSWERS_SHOWN);
	}
	return text;
}

/**
 * WHAT:   Describes an ARP packet the way people say it out loud.
 * WHY:    "who has 192.168.1.1? tell 192.168.1.5" is the standard reading,
 *         also used by tcpdump.
 * RETURN: the description
 *
 * @param arp the decoded ARP packet
 * @return the readable description
 */
std::string describeArp(const ArpPacket& arp)
{
	if (arp.operation == ARP_REQUEST)
	{
		return std::format("who has {}? tell {}", toString(arp.targetIp), toString(arp.senderIp));
	}
	if (arp.operation == ARP_REPLY)
	{
		return std::format("{} is at {}", toString(arp.senderIp), toString(arp.senderMac));
	}
	return std::format("operation {}", arp.operation);
}

/**
 * WHAT:   Pads a protocol label to 6 characters.
 * WHY:    Lines up the addresses in the summary column.
 * RETURN: the padded label
 *
 * @param label e.g. "TCP"
 * @return the label followed by spaces
 */
std::string column(const char* label)
{
	return std::format("{:<6}", label);
}

} // namespace

std::string formatTimestamp(std::int64_t seconds, std::int64_t microseconds)
{
	const auto time = static_cast<std::time_t>(seconds);
	std::tm local{};
#ifdef _WIN32
	localtime_s(&local, &time);
#else
	localtime_r(&time, &local);
#endif
	return std::format("{:02}:{:02}:{:02}.{:06}", local.tm_hour, local.tm_min, local.tm_sec, microseconds);
}

std::string summarize(const DecodedPacket& packet)
{
	std::string line;

	if (packet.dns && packet.udp)
	{
		line = column("DNS") + std::format("{} -> {}  {}",
			endpoint(packet, true, packet.udp->sourcePort), endpoint(packet, false, packet.udp->destinationPort),
			describeDns(*packet.dns));
	}
	else if (packet.tcp)
	{
		const TcpSegment& tcp = *packet.tcp;
		line = column("TCP") + std::format("{} -> {}  [{}] seq={}",
			endpoint(packet, true, tcp.sourcePort), endpoint(packet, false, tcp.destinationPort),
			tcpFlagsToString(tcp.flags), tcp.sequence);
		if ((tcp.flags & tcp_flag::ACK) != 0)
		{
			line += std::format(" ack={}", tcp.acknowledgment);
		}
		line += std::format(" len={}", tcp.payload.size());
	}
	else if (packet.udp)
	{
		line = column("UDP") + std::format("{} -> {}  len={}",
			endpoint(packet, true, packet.udp->sourcePort), endpoint(packet, false, packet.udp->destinationPort),
			packet.udp->payload.size());
	}
	else if (packet.icmp)
	{
		line = column(packet.icmp->version6 ? "ICMPv6" : "ICMP") + std::format("{} -> {}  {}",
			endpoint(packet, true, std::nullopt), endpoint(packet, false, std::nullopt), describeIcmp(*packet.icmp));
	}
	else if (packet.arp)
	{
		line = column("ARP") + describeArp(*packet.arp);
	}
	else if (packet.ipv4)
	{
		line = column("IPv4") + std::format("{} -> {}  protocol {}",
			endpoint(packet, true, std::nullopt), endpoint(packet, false, std::nullopt), packet.ipv4->protocol);
	}
	else if (packet.ipv6)
	{
		line = column("IPv6") + std::format("{} -> {}  next header {}",
			endpoint(packet, true, std::nullopt), endpoint(packet, false, std::nullopt), packet.ipv6->upperProtocol);
	}
	else if (packet.ethernet && packet.ethernet->isLengthField())
	{
		line = column("802.3") + std::format("{} -> {}  length {} (LLC, e.g. spanning tree)",
			toString(packet.ethernet->source), toString(packet.ethernet->destination), packet.ethernet->etherType);
	}
	else if (packet.ethernet)
	{
		line = column("ETH") + std::format("{} -> {}  type 0x{:04x}",
			toString(packet.ethernet->source), toString(packet.ethernet->destination), packet.ethernet->etherType);
	}
	else
	{
		line = column("?") + std::format("{} bytes", packet.capturedLength);
	}

	for (std::size_t i = 0; i < packet.notes.size(); ++i)
	{
		line += (i == 0 ? "  ! " : "; ") + packet.notes[i];
	}
	return line;
}

std::string describeLayers(const DecodedPacket& packet)
{
	std::string text;

	if (packet.ethernet)
	{
		const EthernetFrame& eth = *packet.ethernet;
		text += std::format("    {:<9} {} -> {}  type 0x{:04x}", "Ethernet", toString(eth.source),
			toString(eth.destination), eth.etherType);
		if (eth.vlanId)
		{
			text += std::format("  VLAN {}", *eth.vlanId);
		}
		text += '\n';
	}
	if (packet.arp)
	{
		text += std::format("    {:<9} {}  sender {} {}  target {} {}\n", "ARP", describeArp(*packet.arp),
			toString(packet.arp->senderMac), toString(packet.arp->senderIp),
			toString(packet.arp->targetMac), toString(packet.arp->targetIp));
	}
	if (packet.ipv4)
	{
		const Ipv4Packet& ip = *packet.ipv4;
		text += std::format("    {:<9} {} -> {}  ttl {}  id {}{}{}  header {} B  total {} B  checksum {}\n", "IPv4",
			toString(ip.source), toString(ip.destination), ip.ttl, ip.identification,
			ip.dontFragment ? "  DF" : "", ip.moreFragments ? "  MF" : "",
			ip.headerLength, ip.totalLength, ip.checksumValid ? "ok" : "mismatch");
	}
	if (packet.ipv6)
	{
		const Ipv6Packet& ip = *packet.ipv6;
		text += std::format("    {:<9} {} -> {}  hop limit {}  flow 0x{:05x}  payload {} B", "IPv6",
			toString(ip.source), toString(ip.destination), ip.hopLimit, ip.flowLabel, ip.payloadLength);
		if (!ip.extensionHeaders.empty())
		{
			text += std::format("  {} extension header(s)", ip.extensionHeaders.size());
		}
		text += '\n';
	}
	if (packet.tcp)
	{
		const TcpSegment& tcp = *packet.tcp;
		text += std::format("    {:<9} {} -> {}  [{}]  seq {}  ack {}  window {}  header {} B  payload {} B\n", "TCP",
			tcp.sourcePort, tcp.destinationPort, tcpFlagsToString(tcp.flags), tcp.sequence, tcp.acknowledgment,
			tcp.window, tcp.headerLength, tcp.payload.size());
	}
	if (packet.udp)
	{
		text += std::format("    {:<9} {} -> {}  length {} B\n", "UDP", packet.udp->sourcePort,
			packet.udp->destinationPort, packet.udp->length);
	}
	if (packet.icmp)
	{
		text += std::format("    {:<9} {}  (type {} code {})\n", packet.icmp->version6 ? "ICMPv6" : "ICMP",
			describeIcmp(*packet.icmp), packet.icmp->type, packet.icmp->code);
	}
	if (packet.dns)
	{
		text += std::format("    {:<9} {}\n", "DNS", describeDns(*packet.dns));
		for (const DnsAnswer& answer : packet.dns->answers)
		{
			text += std::format("    {:<9} {} {} {}  ttl {}\n", "", answer.name, dnsTypeName(answer.type), answer.data,
				answer.ttl);
		}
	}
	for (const std::string& note : packet.notes)
	{
		text += std::format("    {:<9} {}\n", "note", note);
	}
	return text;
}

} // namespace wiresight
