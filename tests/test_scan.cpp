#include "demo.hpp"
#include "packet.hpp"
#include "scan.hpp"
#include "test.hpp"
#include "watch.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace
{

using namespace wiresight;

/** WHAT: one second in microseconds. */
constexpr std::int64_t SECOND = 1'000'000;

/**
 * WHAT:   Builds a decoded TCP packet directly, without bytes.
 * WHY:    The detector only reads addresses, ports and flags, so tests can
 *         describe a conversation in one line per packet.
 * RETURN: the packet
 *
 * @param from     source IPv4 address
 * @param to       destination IPv4 address
 * @param fromPort source port
 * @param toPort   destination port
 * @param flags    tcp_flag bits
 * @return the packet
 */
DecodedPacket tcp(Ipv4Address from, Ipv4Address to, std::uint16_t fromPort, std::uint16_t toPort, std::uint8_t flags)
{
	DecodedPacket packet;
	packet.ipv4.emplace();
	packet.ipv4->source = from;
	packet.ipv4->destination = to;
	packet.tcp.emplace();
	packet.tcp->sourcePort = fromPort;
	packet.tcp->destinationPort = toPort;
	packet.tcp->flags = flags;
	return packet;
}

constexpr Ipv4Address SCANNER = {203, 0, 113, 7};
constexpr Ipv4Address TARGET = {198, 51, 100, 20};

/**
 * WHAT:   Removes ANSI escape codes from text.
 * RETURN: the text as a person reads it on screen
 *
 * @param text the frame
 * @return the visible text
 */
std::string visible(const std::string& text)
{
	std::string out;
	for (std::size_t i = 0; i < text.size(); ++i)
	{
		if (text[i] == '\x1b' && i + 1 < text.size() && text[i + 1] == '[')
		{
			i += 2;
			while (i < text.size() && !(text[i] >= '@' && text[i] <= '~'))
			{
				++i;
			}
			continue;
		}
		out += text[i];
	}
	return out;
}

} // namespace

TEST(scanAlertsAtThreshold)
{
	ScanDetector detector(20, 10 * SECOND);
	for (std::uint16_t port = 1; port < 20; ++port)
	{
		CHECK(!detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), port * 1000));
	}
	const auto alert = detector.observe(tcp(SCANNER, TARGET, 40000, 20, tcp_flag::SYN), 20 * 1000);
	CHECK(alert.has_value());
	CHECK_EQ(alert->source, std::string("203.0.113.7"));
	CHECK_EQ(alert->target, std::string("198.51.100.20"));
	CHECK_EQ(alert->ports, std::size_t{20});
	CHECK_EQ(alert->elapsedMicros, std::int64_t{19'000});
}

TEST(scanAlertsOnlyOncePerPair)
{
	ScanDetector detector(5);
	int alerts = 0;
	for (std::uint16_t port = 1; port <= 100; ++port)
	{
		alerts += detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), port) ? 1 : 0;
	}
	CHECK_EQ(alerts, 1);
}

TEST(scanIgnoresManyConnectionsToOnePort)
{
	// a browser opening dozens of connections to one website is not a scan
	ScanDetector detector(20);
	for (std::uint16_t i = 0; i < 200; ++i)
	{
		CHECK(!detector.observe(tcp(SCANNER, TARGET, static_cast<std::uint16_t>(50000 + i), 443, tcp_flag::SYN), i));
	}
}

TEST(scanIgnoresSlowProbesOutsideTheWindow)
{
	// one new port every second against a 10-second window never reaches 20 at once
	ScanDetector detector(20, 10 * SECOND);
	for (std::uint16_t port = 1; port <= 100; ++port)
	{
		CHECK(!detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), port * SECOND));
	}
}

TEST(scanCountsRepeatedPortOnce)
{
	ScanDetector detector(3);
	for (int i = 0; i < 10; ++i)
	{
		CHECK(!detector.observe(tcp(SCANNER, TARGET, 40000, 22, tcp_flag::SYN), i));
		CHECK(!detector.observe(tcp(SCANNER, TARGET, 40000, 80, tcp_flag::SYN), i));
	}
	CHECK(detector.observe(tcp(SCANNER, TARGET, 40000, 443, tcp_flag::SYN), 20).has_value());
}

TEST(scanMarksOpenClosedAndFiltered)
{
	ScanDetector detector;
	detector.observe(tcp(SCANNER, TARGET, 40001, 22, tcp_flag::SYN), 1);
	detector.observe(tcp(SCANNER, TARGET, 40002, 23, tcp_flag::SYN), 2);
	detector.observe(tcp(SCANNER, TARGET, 40003, 137, tcp_flag::SYN), 3);
	detector.observe(tcp(TARGET, SCANNER, 22, 40001, tcp_flag::SYN | tcp_flag::ACK), 4);
	detector.observe(tcp(TARGET, SCANNER, 23, 40002, tcp_flag::RST | tcp_flag::ACK), 5);
	// the scanner's own RST after a connect scan must not mark anything
	detector.observe(tcp(SCANNER, TARGET, 40001, 22, tcp_flag::RST | tcp_flag::ACK), 6);

	const ScanTrack* track = detector.busiest();
	CHECK(track != nullptr);
	CHECK(track->ports.at(22) == PortState::Open);
	CHECK(track->ports.at(23) == PortState::Closed);
	CHECK(track->ports.at(137) == PortState::Probed);
	CHECK_EQ(track->count(PortState::Open), std::size_t{1});
	CHECK(track->lastReply == PortState::Closed);
}

TEST(scanIgnoresAnswersToUnknownProbes)
{
	ScanDetector detector;
	CHECK(!detector.observe(tcp(TARGET, SCANNER, 22, 40001, tcp_flag::SYN | tcp_flag::ACK), 1));
	CHECK_EQ(detector.tracked(), std::size_t{0});
	CHECK(detector.busiest() == nullptr);
}

TEST(scanIgnoresPacketsWithoutTcp)
{
	ScanDetector detector(2);
	DecodedPacket packet;
	packet.ipv4.emplace();
	CHECK(!detector.observe(packet, 1));
	CHECK(!detector.observe(DecodedPacket{}, 2));
	CHECK_EQ(detector.tracked(), std::size_t{0});
}

TEST(scanForgetsIdlePairsButKeepsTheBusiest)
{
	ScanDetector detector;
	for (std::uint16_t port = 1; port <= 50; ++port)
	{
		detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), 0);
	}
	detector.observe(tcp({192, 0, 2, 1}, TARGET, 40000, 80, tcp_flag::SYN), 0);
	CHECK_EQ(detector.tracked(), std::size_t{2});
	// over a thousand quiet packets two minutes later trigger the clean-up
	for (int i = 0; i < 1100; ++i)
	{
		detector.observe(DecodedPacket{}, 120 * SECOND);
	}
	CHECK_EQ(detector.tracked(), std::size_t{1});
	CHECK_EQ(detector.busiest()->source, std::string("203.0.113.7"));
}

TEST(scanHandlesAFullPortRangeQuickly)
{
	// incremental counting: 65,535 probes must not take quadratic time
	ScanDetector detector(20);
	const auto start = std::chrono::steady_clock::now();
	for (std::uint32_t port = 1; port <= 65535; ++port)
	{
		detector.observe(tcp(SCANNER, TARGET, 40000, static_cast<std::uint16_t>(port), tcp_flag::SYN), port);
	}
	const auto took = std::chrono::steady_clock::now() - start;
	CHECK(took < std::chrono::seconds(2));
	CHECK_EQ(detector.busiest()->ports.size(), std::size_t{65535});
}

TEST(demoRaisesOneAlertAndFindsTheOpenPorts)
{
	const std::vector<DemoPacket> packets = scanDemo();
	CHECK(std::is_sorted(packets.begin(), packets.end(),
		[](const DemoPacket& a, const DemoPacket& b) { return a.offsetMicros < b.offsetMicros; }));

	ScanDetector detector;
	int alerts = 0;
	for (const DemoPacket& demo : packets)
	{
		const DecodedPacket packet = decode(Bytes(demo.frame), LinkType::Ethernet, demo.frame.size());
		CHECK(packet.notes.empty());
		alerts += detector.observe(packet, demo.offsetMicros) ? 1 : 0;
	}
	CHECK_EQ(alerts, 1);
	const ScanTrack* track = detector.busiest();
	CHECK_EQ(track->source, std::string(DEMO_SCANNER));
	CHECK_EQ(track->target, std::string(DEMO_TARGET));
	CHECK_EQ(track->ports.size(), std::size_t{1024});
	CHECK_EQ(track->count(PortState::Open), std::size_t{4});
	CHECK_EQ(track->count(PortState::Probed), std::size_t{5}); // 135 to 139, filtered
	CHECK_EQ(track->count(PortState::Closed), std::size_t{1015});
}

TEST(watchFrameHasFixedHeightAndShowsTheScan)
{
	ScanDetector detector(3);
	std::optional<ScanAlert> alert;
	for (std::uint16_t port : {21, 22, 23, 80})
	{
		if (auto raised = detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), port))
		{
			alert = raised;
		}
	}
	detector.observe(tcp(TARGET, SCANNER, 22, 40000, tcp_flag::SYN | tcp_flag::ACK), 100);

	WatchStatus status{.sourceLabel = "DEMO", .packets = 12345, .nowMicros = 100, .alert = alert, .finished = false};
	const std::string frame = visible(renderWatch(detector.busiest(), status, 3));
	CHECK_EQ(static_cast<int>(std::count(frame.begin(), frame.end(), '\n')), WATCH_LINES);
	CHECK(frame.find("12,345 packets") != std::string::npos);
	CHECK(frame.find("203.0.113.7") != std::string::npos);
	CHECK(frame.find("198.51.100.20") != std::string::npos);
	CHECK(frame.find("4 / 1,024") != std::string::npos);
	CHECK(frame.find("OPEN 1") != std::string::npos);
	CHECK(frame.find("SYN probes → 4") != std::string::npos);
	CHECK(frame.find("22 ssh") != std::string::npos);
	CHECK(frame.find("PORT SCAN") != std::string::npos);
}

TEST(watchFrameWithNothingSeen)
{
	WatchStatus status;
	status.sourceLabel = "LIVE";
	const std::string frame = visible(renderWatch(nullptr, status, 0));
	CHECK_EQ(static_cast<int>(std::count(frame.begin(), frame.end(), '\n')), WATCH_LINES);
	CHECK(frame.find("no scan detected") != std::string::npos);
	CHECK(frame.find("no TCP connection attempts seen yet") != std::string::npos);
}

TEST(watchFrameEdgesLineUp)
{
	// every framed line (title to bottom border) is 78 columns, so the box's right edge is straight
	const std::vector<DemoPacket> packets = scanDemo();
	ScanDetector detector;
	WatchStatus status;
	status.sourceLabel = "DEMO";
	for (const DemoPacket& demo : packets)
	{
		const DecodedPacket packet = decode(Bytes(demo.frame), LinkType::Ethernet, demo.frame.size());
		if (auto alert = detector.observe(packet, demo.offsetMicros))
		{
			status.alert = alert;
		}
		++status.packets;
	}
	for (const ScanTrack* track : {static_cast<const ScanTrack*>(nullptr), detector.busiest()})
	{
		const std::string frame = visible(renderWatch(track, status, 1));
		std::size_t start = 0;
		for (int line = 0; line < 25; ++line)
		{
			const std::size_t end = frame.find('\n', start);
			const std::string text = frame.substr(start, end - start);
			const auto columns = std::count_if(text.begin(), text.end(),
				[](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; });
			CHECK_EQ(columns, std::ptrdiff_t{78});
			start = end + 1;
		}
	}
}

TEST(serviceNames)
{
	CHECK_EQ(serviceName(22), std::string("ssh"));
	CHECK_EQ(serviceName(443), std::string("https"));
	CHECK_EQ(serviceName(12345), std::string(""));
}
