#include "ethernet.hpp"

namespace wiresight
{

std::optional<EthernetFrame> parseEthernet(Bytes frame)
{
	constexpr std::size_t BASE_LENGTH = 14;
	constexpr std::size_t VLAN_TAG_LENGTH = 4;

	if (frame.size() < BASE_LENGTH)
	{
		return std::nullopt;
	}

	EthernetFrame out;
	out.destination = readArray<6>(frame, 0);
	out.source = readArray<6>(frame, 6);
	out.etherType = readU16(frame, 12);
	out.headerLength = BASE_LENGTH;

	if (out.etherType == ETHERTYPE_VLAN)
	{
		if (frame.size() < BASE_LENGTH + VLAN_TAG_LENGTH)
		{
			return std::nullopt;
		}
		// the low 12 bits of the tag are the VLAN number; the real type follows the tag
		out.vlanId = static_cast<std::uint16_t>(readU16(frame, 14) & 0x0FFF);
		out.etherType = readU16(frame, 16);
		out.headerLength = BASE_LENGTH + VLAN_TAG_LENGTH;
	}

	out.payload = frame.subspan(out.headerLength);
	return out;
}

} // namespace wiresight
