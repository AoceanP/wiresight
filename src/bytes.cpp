#include "bytes.hpp"

#include <format>

namespace wiresight
{

std::string toString(const MacAddress& address)
{
	return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
		address[0], address[1], address[2], address[3], address[4], address[5]);
}

std::string toString(const Ipv4Address& address)
{
	return std::format("{}.{}.{}.{}", address[0], address[1], address[2], address[3]);
}

std::string toString(const Ipv6Address& address)
{
	std::array<std::uint16_t, 8> groups{};
	for (std::size_t i = 0; i < groups.size(); ++i)
	{
		groups[i] = static_cast<std::uint16_t>(address[2 * i] << 8 | address[2 * i + 1]);
	}

	// find the longest run of zero groups; RFC 5952 only shortens runs of 2 or more
	std::size_t bestStart = groups.size();
	std::size_t bestLength = 0;
	for (std::size_t i = 0; i < groups.size();)
	{
		if (groups[i] != 0)
		{
			++i;
			continue;
		}
		std::size_t end = i;
		while (end < groups.size() && groups[end] == 0)
		{
			++end;
		}
		if (end - i > bestLength)
		{
			bestStart = i;
			bestLength = end - i;
		}
		i = end;
	}
	if (bestLength < 2)
	{
		bestStart = groups.size();
	}

	std::string text;
	for (std::size_t i = 0; i < groups.size(); ++i)
	{
		if (i == bestStart)
		{
			text += "::";
			i += bestLength - 1;
			continue;
		}
		if (!text.empty() && text.back() != ':')
		{
			text += ':';
		}
		text += std::format("{:x}", groups[i]);
	}
	return text;
}

} // namespace wiresight
