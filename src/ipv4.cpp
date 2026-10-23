#include "ipv4.hpp"

namespace wiresight
{

std::uint16_t internetChecksum(Bytes data)
{
	std::uint32_t sum = 0;
	for (std::size_t i = 0; i + 1 < data.size(); i += 2)
	{
		sum += readU16(data, i);
	}
	if (data.size() % 2 == 1)
	{
		sum += static_cast<std::uint32_t>(data.back()) << 8;
	}
	// fold the carries back in until the sum fits in 16 bits
	while (sum >> 16 != 0)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return static_cast<std::uint16_t>(~sum);
}

std::optional<Ipv4Packet> parseIpv4(Bytes data)
{
	constexpr std::size_t MIN_HEADER = 20;

	if (data.size() < MIN_HEADER || (data[0] >> 4) != 4)
	{
		return std::nullopt;
	}

	Ipv4Packet out;
	out.headerLength = static_cast<std::size_t>(data[0] & 0x0F) * 4;
	if (out.headerLength < MIN_HEADER || out.headerLength > data.size())
	{
		return std::nullopt;
	}
	out.totalLength = readU16(data, 2);
	if (out.totalLength < out.headerLength)
	{
		return std::nullopt;
	}

	out.identification = readU16(data, 4);
	const std::uint16_t flags = readU16(data, 6);
	out.dontFragment = (flags & 0x4000) != 0;
	out.moreFragments = (flags & 0x2000) != 0;
	out.fragmentOffset = static_cast<std::size_t>(flags & 0x1FFF) * 8;
	out.ttl = data[8];
	out.protocol = data[9];
	out.checksum = readU16(data, 10);
	out.checksumValid = internetChecksum(data.first(out.headerLength)) == 0;
	out.source = readArray<4>(data, 12);
	out.destination = readArray<4>(data, 16);

	// Ethernet pads short frames to 60 bytes, so trust the length field, not the frame size
	const std::size_t end = std::min<std::size_t>(out.totalLength, data.size());
	out.truncated = out.totalLength > data.size();
	out.payload = data.subspan(out.headerLength, end - out.headerLength);
	return out;
}

} // namespace wiresight
