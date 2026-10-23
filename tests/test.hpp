#pragma once

#include "bytes.hpp"
#include "ipv4.hpp"

#include <cstdint>
#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

/**
 * WHAT:   A tiny test framework: TEST registers a function, CHECK and
 *         CHECK_EQ fail it with the file, line and values.
 * WHY:    Keeps the project free of downloads and dependencies, the same
 *         way the program itself only needs the standard library and pcap.
 */
namespace test
{

/** WHAT: one registered test. */
struct Case
{
	/** WHAT: the test function's name. */
	const char* name;
	/** WHAT: the test body. */
	std::function<void()> body;
};

/**
 * WHAT:   The list of all tests.
 * WHY:    A function-local static avoids the static initialisation order
 *         problem between test files.
 * RETURN: the shared list
 *
 * @return every registered test
 */
inline std::vector<Case>& registry()
{
	static std::vector<Case> cases;
	return cases;
}

/** WHAT: registers a test when its file is loaded. */
struct Register
{
	/**
	 * WHAT:   Adds a test to the registry.
	 *
	 * @param name the test name
	 * @param body the test function
	 */
	Register(const char* name, std::function<void()> body)
	{
		registry().push_back({name, std::move(body)});
	}
};

/** WHAT: thrown by a failed CHECK; carries the message. */
struct Failure
{
	/** WHAT: where and why the check failed. */
	std::string message;
};

/**
 * WHAT:   Turns hex text like "45 00 00 2c" into bytes.
 * WHY:    Test packets are written exactly as Wireshark shows them.
 * RETURN: the bytes; spaces and anything that is not a hex digit are skipped
 *
 * @param text the hex text
 * @return the bytes
 */
inline std::vector<std::uint8_t> hex(std::string_view text)
{
	std::vector<std::uint8_t> bytes;
	int high = -1;
	for (const char c : text)
	{
		int value;
		if (c >= '0' && c <= '9') value = c - '0';
		else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
		else continue;

		if (high < 0)
		{
			high = value;
		}
		else
		{
			bytes.push_back(static_cast<std::uint8_t>(high << 4 | value));
			high = -1;
		}
	}
	return bytes;
}

/**
 * WHAT:   Writes the correct IPv4 header checksum into a test packet.
 * WHY:    Hand-written headers are easy to get wrong; computing the
 *         checksum keeps the fixtures realistic.
 * PRE:    packet holds a complete IPv4 header at ipOffset
 * POST:   bytes ipOffset+10 and +11 hold the checksum
 *
 * @param packet   the test bytes
 * @param ipOffset where the IPv4 header starts
 */
inline void fixIpv4Checksum(std::vector<std::uint8_t>& packet, std::size_t ipOffset)
{
	const std::size_t headerLength = static_cast<std::size_t>(packet[ipOffset] & 0x0F) * 4;
	packet[ipOffset + 10] = 0;
	packet[ipOffset + 11] = 0;
	const std::uint16_t sum = wiresight::internetChecksum(wiresight::Bytes(packet).subspan(ipOffset, headerLength));
	packet[ipOffset + 10] = static_cast<std::uint8_t>(sum >> 8);
	packet[ipOffset + 11] = static_cast<std::uint8_t>(sum & 0xFF);
}

} // namespace test

/** WHAT: declares and registers a test function. */
#define TEST(name)                                         \
	static void name();                                    \
	static const test::Register name##_registration(#name, name); \
	static void name()

/** WHAT: fails the test when cond is false. */
#define CHECK(cond)                                                                                     \
	do                                                                                                  \
	{                                                                                                   \
		if (!(cond))                                                                                    \
		{                                                                                               \
			throw test::Failure{std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": CHECK(" #cond ") failed"}; \
		}                                                                                               \
	} while (false)

/** WHAT: fails the test when a != b, printing both values. */
#define CHECK_EQ(a, b)                                                                                  \
	do                                                                                                  \
	{                                                                                                   \
		const auto& checkA = (a);                                                                       \
		const auto& checkB = (b);                                                                       \
		if (!(checkA == checkB))                                                                        \
		{                                                                                               \
			std::ostringstream checkMessage;                                                            \
			checkMessage << __FILE__ << ":" << __LINE__ << ": " #a " == " #b " failed: got [" << checkA  \
						 << "] and [" << checkB << "]";                                                 \
			throw test::Failure{checkMessage.str()};                                                    \
		}                                                                                               \
	} while (false)
