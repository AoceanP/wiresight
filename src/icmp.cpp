#include "icmp.hpp"

#include <format>

namespace wiresight
{

namespace
{

/**
 * WHAT:   Tells whether a message is a ping request or reply.
 * WHY:    Only echo messages carry an identifier and sequence number.
 * RETURN: true for ICMP types 0/8 or ICMPv6 types 128/129
 *
 * @param message the decoded message
 * @return whether it is an echo message
 */
bool isEcho(const IcmpMessage& message)
{
	return message.version6 ? (message.type == 128 || message.type == 129) : (message.type == 0 || message.type == 8);
}

/**
 * WHAT:   Names the reason in an ICMP "destination unreachable" message.
 * WHY:    "port" means a closed UDP port; "administratively prohibited"
 *         means a firewall said no.
 * RETURN: the reason, or "code N"
 *
 * @param code the ICMP code
 * @return the readable reason
 */
std::string unreachableReason(std::uint8_t code)
{
	switch (code)
	{
	case 0: return "network";
	case 1: return "host";
	case 2: return "protocol";
	case 3: return "port";
	case 4: return "fragmentation needed";
	case 13: return "administratively prohibited";
	default: return std::format("code {}", code);
	}
}

/**
 * WHAT:   Describes an ICMP (IPv4) message type.
 * WHY:    ICMP and ICMPv6 use different numbers for the same ideas.
 * RETURN: the description, or "type T code C"
 *
 * @param message the decoded message
 * @return the readable description
 */
std::string describeV4(const IcmpMessage& message)
{
	switch (message.type)
	{
	case 0: return "echo reply";
	case 3: return "destination unreachable (" + unreachableReason(message.code) + ")";
	case 5: return "redirect";
	case 8: return "echo request";
	case 11: return "time exceeded";
	default: return std::format("type {} code {}", message.type, message.code);
	}
}

/**
 * WHAT:   Describes an ICMPv6 message type.
 * WHY:    IPv6 also uses ICMPv6 for neighbour discovery, its version of ARP.
 * RETURN: the description, or "type T code C"
 *
 * @param message the decoded message
 * @return the readable description
 */
std::string describeV6(const IcmpMessage& message)
{
	switch (message.type)
	{
	case 1: return "destination unreachable";
	case 2: return "packet too big";
	case 3: return "time exceeded";
	case 128: return "echo request";
	case 129: return "echo reply";
	case 133: return "router solicitation";
	case 134: return "router advertisement";
	case 135: return "neighbor solicitation";
	case 136: return "neighbor advertisement";
	default: return std::format("type {} code {}", message.type, message.code);
	}
}

} // namespace

std::optional<IcmpMessage> parseIcmp(Bytes data, bool version6)
{
	if (data.size() < 4)
	{
		return std::nullopt;
	}

	IcmpMessage out;
	out.version6 = version6;
	out.type = data[0];
	out.code = data[1];
	// echo messages carry an identifier and sequence number after the checksum
	if (isEcho(out) && data.size() >= 8)
	{
		out.identifier = readU16(data, 4);
		out.sequence = readU16(data, 6);
	}
	return out;
}

std::string describeIcmp(const IcmpMessage& message)
{
	std::string text = message.version6 ? describeV6(message) : describeV4(message);
	if (message.identifier && message.sequence)
	{
		text += std::format(" id={} seq={}", *message.identifier, *message.sequence);
	}
	return text;
}

} // namespace wiresight
