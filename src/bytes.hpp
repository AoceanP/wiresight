#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace wiresight
{

/**
 * WHAT:   A read-only view of raw packet bytes.
 * WHY:    std::span carries its own length, so every decoder can check
 *         bounds before it reads; a raw pointer could not.
 */
using Bytes = std::span<const std::uint8_t>;

/** WHAT: a 6-byte Ethernet hardware (MAC) address. */
using MacAddress = std::array<std::uint8_t, 6>;

/** WHAT: a 4-byte IPv4 address, first octet first. */
using Ipv4Address = std::array<std::uint8_t, 4>;

/** WHAT: a 16-byte IPv6 address. */
using Ipv6Address = std::array<std::uint8_t, 16>;

/**
 * WHAT:   Reads a 16-bit number stored big-endian.
 * WHY:    Network byte order is big-endian, but x86 and ARM PCs are
 *         little-endian, so the two bytes are combined by hand instead of
 *         casting a pointer (which would also break alignment rules).
 * PRE:    offset + 2 <= data.size()
 * RETURN: the number
 *
 * @param data   the bytes to read from
 * @param offset where the number starts
 * @return the 16-bit value
 */
inline std::uint16_t readU16(Bytes data, std::size_t offset)
{
	return static_cast<std::uint16_t>(data[offset] << 8 | data[offset + 1]);
}

/**
 * WHAT:   Reads a 32-bit number stored big-endian.
 * WHY:    Same reason as readU16, for sequence numbers and TTLs.
 * PRE:    offset + 4 <= data.size()
 * RETURN: the number
 *
 * @param data   the bytes to read from
 * @param offset where the number starts
 * @return the 32-bit value
 */
inline std::uint32_t readU32(Bytes data, std::size_t offset)
{
	return static_cast<std::uint32_t>(data[offset]) << 24 | static_cast<std::uint32_t>(data[offset + 1]) << 16
		| static_cast<std::uint32_t>(data[offset + 2]) << 8 | static_cast<std::uint32_t>(data[offset + 3]);
}

/**
 * WHAT:   Copies N bytes into a fixed-size array, e.g. an address.
 * WHY:    Addresses are kept by value, so a decoded packet never points
 *         into a buffer that may already be gone.
 * PRE:    offset + N <= data.size()
 * RETURN: the copied bytes
 *
 * @tparam N     how many bytes to copy
 * @param data   the bytes to read from
 * @param offset where the bytes start
 * @return the bytes as an array
 */
template <std::size_t N>
std::array<std::uint8_t, N> readArray(Bytes data, std::size_t offset)
{
	std::array<std::uint8_t, N> out{};
	std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(offset), N, out.begin());
	return out;
}

/**
 * WHAT:   Formats a MAC address as "aa:bb:cc:dd:ee:ff".
 * WHY:    The usual lowercase, colon-separated form Wireshark also uses.
 * RETURN: the address as text
 *
 * @param address the MAC address
 * @return the formatted text
 */
std::string toString(const MacAddress& address);

/**
 * WHAT:   Formats an IPv4 address as "192.168.1.5".
 * WHY:    Dotted decimal is what every network tool prints.
 * RETURN: the address as text
 *
 * @param address the IPv4 address
 * @return the formatted text
 */
std::string toString(const Ipv4Address& address);

/**
 * WHAT:   Formats an IPv6 address in the short form of RFC 5952, e.g. "fe80::1".
 * WHY:    The longest run of zero groups becomes "::", which is the only
 *         form people (and other tools) expect to read.
 * RETURN: the address as text
 *
 * @param address the IPv6 address
 * @return the formatted text
 */
std::string toString(const Ipv6Address& address);

} // namespace wiresight
