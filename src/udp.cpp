#include "udp.hpp"

namespace wiresight
{

std::optional<UdpDatagram> parseUdp(Bytes data)
{
	constexpr std::size_t HEADER = 8;

	if (data.size() < HEADER)
	{
		return std::nullopt;
	}

	UdpDatagram out;
	out.sourcePort = readU16(data, 0);
	out.destinationPort = readU16(data, 2);
	out.length = readU16(data, 4);
	if (out.length < HEADER)
	{
		return std::nullopt;
	}

	const std::size_t end = std::min<std::size_t>(out.length, data.size());
	out.truncated = out.length > data.size();
	out.payload = data.subspan(HEADER, end - HEADER);
	return out;
}

} // namespace wiresight
