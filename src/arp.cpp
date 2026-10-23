#include "arp.hpp"

#include "ethernet.hpp"

namespace wiresight
{

std::optional<ArpPacket> parseArp(Bytes data)
{
	constexpr std::size_t LENGTH = 28;
	constexpr std::uint16_t HARDWARE_ETHERNET = 1;

	if (data.size() < LENGTH)
	{
		return std::nullopt;
	}
	// hardware type, protocol type, and the two address sizes must match Ethernet + IPv4
	if (readU16(data, 0) != HARDWARE_ETHERNET || readU16(data, 2) != ETHERTYPE_IPV4 || data[4] != 6 || data[5] != 4)
	{
		return std::nullopt;
	}

	ArpPacket out;
	out.operation = readU16(data, 6);
	out.senderMac = readArray<6>(data, 8);
	out.senderIp = readArray<4>(data, 14);
	out.targetMac = readArray<6>(data, 18);
	out.targetIp = readArray<4>(data, 24);
	return out;
}

} // namespace wiresight
