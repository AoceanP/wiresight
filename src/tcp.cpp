#include "tcp.hpp"

#include <utility>

namespace wiresight
{

std::optional<TcpSegment> parseTcp(Bytes data)
{
	constexpr std::size_t MIN_HEADER = 20;

	if (data.size() < MIN_HEADER)
	{
		return std::nullopt;
	}

	TcpSegment out;
	out.sourcePort = readU16(data, 0);
	out.destinationPort = readU16(data, 2);
	out.sequence = readU32(data, 4);
	out.acknowledgment = readU32(data, 8);
	// the high 4 bits of byte 12 are the header length in 32-bit words
	out.headerLength = static_cast<std::size_t>(data[12] >> 4) * 4;
	if (out.headerLength < MIN_HEADER || out.headerLength > data.size())
	{
		return std::nullopt;
	}
	out.flags = data[13];
	out.window = readU16(data, 14);
	out.payload = data.subspan(out.headerLength);
	return out;
}

std::string tcpFlagsToString(std::uint8_t flags)
{
	static constexpr std::pair<std::uint8_t, const char*> NAMES[] = {
		{tcp_flag::SYN, "SYN"}, {tcp_flag::FIN, "FIN"}, {tcp_flag::RST, "RST"}, {tcp_flag::PSH, "PSH"},
		{tcp_flag::ACK, "ACK"}, {tcp_flag::URG, "URG"}, {tcp_flag::ECE, "ECE"}, {tcp_flag::CWR, "CWR"},
	};

	std::string text;
	for (const auto& [bit, name] : NAMES)
	{
		if ((flags & bit) != 0)
		{
			if (!text.empty())
			{
				text += ", ";
			}
			text += name;
		}
	}
	return text.empty() ? "none" : text;
}

} // namespace wiresight
