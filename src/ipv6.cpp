#include "ipv6.hpp"

namespace wiresight
{

namespace
{

constexpr std::size_t FIXED_HEADER = 40;
constexpr std::size_t MAX_EXTENSION_HEADERS = 8;

constexpr std::uint8_t HOP_BY_HOP = 0;
constexpr std::uint8_t ROUTING = 43;
constexpr std::uint8_t FRAGMENT = 44;
constexpr std::uint8_t DESTINATION_OPTIONS = 60;

} // namespace

std::optional<Ipv6Packet> parseIpv6(Bytes data)
{
	if (data.size() < FIXED_HEADER || (data[0] >> 4) != 6)
	{
		return std::nullopt;
	}

	Ipv6Packet out;
	const std::uint32_t first = readU32(data, 0);
	out.trafficClass = static_cast<std::uint8_t>(first >> 20 & 0xFF);
	out.flowLabel = first & 0xFFFFF;
	out.payloadLength = readU16(data, 4);
	out.nextHeader = data[6];
	out.hopLimit = data[7];
	out.source = readArray<16>(data, 8);
	out.destination = readArray<16>(data, 24);

	const std::size_t end = std::min<std::size_t>(FIXED_HEADER + out.payloadLength, data.size());
	out.truncated = FIXED_HEADER + out.payloadLength > data.size();
	const Bytes body = data.subspan(FIXED_HEADER, end - FIXED_HEADER);

	std::uint8_t protocol = out.nextHeader;
	std::size_t offset = 0;
	for (std::size_t i = 0; i < MAX_EXTENSION_HEADERS; ++i)
	{
		if (protocol == HOP_BY_HOP || protocol == ROUTING || protocol == DESTINATION_OPTIONS)
		{
			// byte 1 is the length in 8-byte units, not counting the first 8 bytes
			if (offset + 2 > body.size())
			{
				break;
			}
			const std::size_t length = (static_cast<std::size_t>(body[offset + 1]) + 1) * 8;
			if (offset + length > body.size())
			{
				break;
			}
			out.extensionHeaders.push_back(protocol);
			protocol = body[offset];
			offset += length;
		}
		else if (protocol == FRAGMENT)
		{
			// the fragment header is always 8 bytes; the offset is in 8-byte units
			if (offset + 8 > body.size())
			{
				break;
			}
			out.extensionHeaders.push_back(protocol);
			out.fragmented = true;
			out.fragmentOffset = static_cast<std::size_t>(readU16(body, offset + 2) >> 3) * 8;
			protocol = body[offset];
			offset += 8;
		}
		else
		{
			break;
		}
	}

	out.upperProtocol = protocol;
	out.upperPayload = body.subspan(offset);
	return out;
}

} // namespace wiresight
