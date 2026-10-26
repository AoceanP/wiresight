#include "demo.hpp"

#include "bytes.hpp"
#include "ipv4.hpp"
#include "tcp.hpp"

#include <algorithm>
#include <array>

namespace wiresight
{

namespace
{

/** WHAT: an IPv4 address as four numbers. */
using Ip = std::array<std::uint8_t, 4>;

constexpr Ip SCANNER = {203, 0, 113, 7};
constexpr Ip TARGET = {198, 51, 100, 20};
constexpr Ip LAPTOP = {192, 0, 2, 10};
constexpr Ip WEBSITE = {203, 0, 113, 80};

/** WHAT: scan speed: one probe every this many microseconds (about 140 ports a second). */
constexpr std::int64_t PROBE_GAP = 7'000;
/** WHAT: the target's answer comes this long after the probe (a LAN round trip). */
constexpr std::int64_t REPLY_DELAY = 1'500;
/** WHAT: when the scan starts, after the normal traffic. */
constexpr std::int64_t SCAN_START = 1'500'000;

/**
 * WHAT:   Builds an Ethernet + IPv4 + TCP frame with no payload.
 * RETURN: the frame, with a correct IPv4 header checksum
 *
 * @param from    source address
 * @param to      destination address
 * @param fromPort source port
 * @param toPort  destination port
 * @param flags   tcp_flag bits
 * @return the frame bytes
 */
std::vector<std::uint8_t> tcpFrame(const Ip& from, const Ip& to, std::uint16_t fromPort, std::uint16_t toPort,
	std::uint8_t flags)
{
	std::vector<std::uint8_t> f = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, // Ethernet, IPv4
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,             // IPv4, 40 bytes, TTL 64
	};
	f.insert(f.end(), from.begin(), from.end());
	f.insert(f.end(), to.begin(), to.end());
	const std::uint8_t tcp[] = {
		static_cast<std::uint8_t>(fromPort >> 8), static_cast<std::uint8_t>(fromPort),
		static_cast<std::uint8_t>(toPort >> 8), static_cast<std::uint8_t>(toPort),
		0x00, 0x00, 0x10, 0x00, // sequence
		0x00, 0x00, 0x00, 0x00, // acknowledgment
		0x50, flags, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
	};
	f.insert(f.end(), std::begin(tcp), std::end(tcp));

	const std::uint16_t sum = internetChecksum(Bytes(f).subspan(14, 20));
	f[24] = static_cast<std::uint8_t>(sum >> 8);
	f[25] = static_cast<std::uint8_t>(sum & 0xFF);
	return f;
}

} // namespace

std::vector<DemoPacket> scanDemo()
{
	std::vector<DemoPacket> out;
	const auto add = [&out](std::int64_t at, std::vector<std::uint8_t> frame) {
		out.push_back({at, std::move(frame)});
	};

	// normal browsing first: many connections, but all to port 443, so no alert
	for (int i = 0; i < 6; ++i)
	{
		const std::int64_t at = 100'000 + i * 200'000;
		const auto clientPort = static_cast<std::uint16_t>(51000 + i);
		add(at, tcpFrame(LAPTOP, WEBSITE, clientPort, 443, tcp_flag::SYN));
		add(at + 20'000, tcpFrame(WEBSITE, LAPTOP, 443, clientPort, tcp_flag::SYN | tcp_flag::ACK));
		add(at + 20'100, tcpFrame(LAPTOP, WEBSITE, clientPort, 443, tcp_flag::ACK));
	}

	// the scan: a TCP connect to every port from 1 to 1024
	constexpr std::array<std::uint16_t, 4> OPEN = {22, 80, 443, 445};
	for (std::uint16_t port = 1; port <= 1024; ++port)
	{
		const std::int64_t at = SCAN_START + (port - 1) * PROBE_GAP;
		const auto scanPort = static_cast<std::uint16_t>(40000 + port);
		add(at, tcpFrame(SCANNER, TARGET, scanPort, port, tcp_flag::SYN));
		if (port >= 135 && port <= 139)
		{
			continue; // filtered: a firewall drops the probe, nothing comes back
		}
		if (std::find(OPEN.begin(), OPEN.end(), port) != OPEN.end())
		{
			add(at + REPLY_DELAY, tcpFrame(TARGET, SCANNER, port, scanPort, tcp_flag::SYN | tcp_flag::ACK));
			add(at + REPLY_DELAY + 100, tcpFrame(SCANNER, TARGET, scanPort, port, tcp_flag::ACK));
			add(at + REPLY_DELAY + 200, tcpFrame(SCANNER, TARGET, scanPort, port, tcp_flag::RST | tcp_flag::ACK));
		}
		else
		{
			add(at + REPLY_DELAY, tcpFrame(TARGET, SCANNER, port, scanPort, tcp_flag::RST | tcp_flag::ACK));
		}
	}

	std::stable_sort(out.begin(), out.end(),
		[](const DemoPacket& a, const DemoPacket& b) { return a.offsetMicros < b.offsetMicros; });
	return out;
}

} // namespace wiresight
