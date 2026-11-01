#include "packet.hpp"
#include "scan.hpp"
#include "test.hpp"
#include "watch.hpp"

#include <algorithm>
#include <string>

namespace
{

using namespace wiresight;

/** WHAT: one second in microseconds. */
constexpr std::int64_t SECOND = 1'000'000;

constexpr Ipv4Address SCANNER = {203, 0, 113, 7};
constexpr Ipv4Address TARGET = {198, 51, 100, 20};

/**
 * WHAT:   Builds a decoded IPv4 TCP packet directly, without bytes.
 * RETURN: the packet
 *
 * @param from     source address
 * @param to       destination address
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

/**
 * WHAT:   A SYN to port 22 on host .N of 198.51.100.0/24.
 * RETURN: the packet
 *
 * @param host the last byte of the address
 * @return the packet
 */
DecodedPacket sshProbe(int host)
{
	return tcp(SCANNER, {198, 51, 100, static_cast<std::uint8_t>(host)}, 50000, 22, tcp_flag::SYN);
}

/**
 * WHAT:   A forged source address, different for every n below 2^24.
 * WHY:    A SYN flood's addresses are random; each one is a new pair.
 * RETURN: an address in 10.0.0.0/8
 *
 * @param n which address
 * @return the address
 */
Ipv4Address forged(int n)
{
	return {10, static_cast<std::uint8_t>(n >> 16), static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)};
}

/** WHAT: removes ANSI escape codes, leaving what a person sees. */
std::string visible(const std::string& text)
{
	std::string out;
	for (std::size_t i = 0; i < text.size(); ++i)
	{
		if (text[i] == '\x1b')
		{
			while (i < text.size() && !std::isalpha(static_cast<unsigned char>(text[i])))
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

TEST(sweepAlertsAtThreshold)
{
	ScanDetector detector(20, 10 * SECOND, 20);
	for (int host = 1; host < 20; ++host)
	{
		CHECK(!detector.observe(sshProbe(host), host * 1000));
	}
	const auto alert = detector.observe(sshProbe(20), 20 * 1000);
	CHECK(alert.has_value());
	CHECK(alert->kind == ScanKind::HostSweep);
	CHECK_EQ(alert->source, std::string("203.0.113.7"));
	CHECK_EQ(alert->target, std::string("198.51.100.0/24"));
	CHECK_EQ(alert->port, std::uint16_t{22});
	CHECK_EQ(alert->hosts, std::size_t{20});
	CHECK_EQ(alert->elapsedMicros, std::int64_t{19'000});
}

TEST(sweepAlertsOnlyOnce)
{
	ScanDetector detector(20, 10 * SECOND, 5);
	int alerts = 0;
	for (int host = 1; host <= 200; ++host)
	{
		alerts += detector.observe(sshProbe(host), host) ? 1 : 0;
	}
	CHECK_EQ(alerts, 1);
}

TEST(sweepIgnoresBelowThreshold)
{
	ScanDetector detector(20, 10 * SECOND, 20);
	for (int host = 1; host < 20; ++host)
	{
		CHECK(!detector.observe(sshProbe(host), host));
	}
}

TEST(sweepIgnoresSlowProbesOutsideTheWindow)
{
	// one host a second against a 10-second window never has 20 at once
	ScanDetector detector(20, 10 * SECOND, 20);
	for (int host = 1; host <= 200; ++host)
	{
		CHECK(!detector.observe(sshProbe(host), host * SECOND));
	}
}

TEST(sweepIgnoresOneHostManyTimes)
{
	ScanDetector detector(20, 10 * SECOND, 3);
	for (int i = 0; i < 50; ++i)
	{
		CHECK(!detector.observe(sshProbe(9), i));
	}
}

TEST(sweepIgnoresServersAcrossTheInternet)
{
	// a browser reaching 60 different content servers on 443 within a second: every one in a
	// different /24, so it is normal browsing, not a sweep of one network
	ScanDetector detector(20, 10 * SECOND, 20);
	for (int i = 0; i < 60; ++i)
	{
		const Ipv4Address server = {static_cast<std::uint8_t>(20 + i), 10, static_cast<std::uint8_t>(i), 5};
		CHECK(!detector.observe(tcp({192, 0, 2, 10}, server, static_cast<std::uint16_t>(51000 + i), 443, tcp_flag::SYN),
			i * 10'000));
	}
}

TEST(sweepUsesSlash64ForIpv6)
{
	ScanDetector detector(20, 10 * SECOND, 3);
	std::optional<ScanAlert> alert;
	for (std::uint8_t host = 1; host <= 3; ++host)
	{
		DecodedPacket packet;
		packet.ipv6.emplace();
		packet.ipv6->source = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
		packet.ipv6->destination = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, host};
		packet.tcp.emplace();
		packet.tcp->destinationPort = 3389;
		packet.tcp->flags = tcp_flag::SYN;
		alert = detector.observe(packet, host);
	}
	CHECK(alert.has_value());
	CHECK_EQ(alert->target, std::string("2001:db8:0:1::/64"));
	CHECK_EQ(alert->port, std::uint16_t{3389});
}

TEST(sweepAndPortScanAreSeparateAlerts)
{
	// a port scan of one host, then a sweep of its neighbours: two different alerts
	ScanDetector detector(20, 10 * SECOND, 20);
	std::vector<ScanKind> kinds;
	for (std::uint16_t port = 1; port <= 30; ++port)
	{
		if (auto alert = detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), port))
		{
			kinds.push_back(alert->kind);
		}
	}
	for (int host = 1; host <= 30; ++host)
	{
		if (auto alert = detector.observe(sshProbe(host), 100 + host))
		{
			kinds.push_back(alert->kind);
		}
	}
	CHECK_EQ(kinds.size(), std::size_t{2});
	CHECK(kinds[0] == ScanKind::PortScan);
	CHECK(kinds[1] == ScanKind::HostSweep);
	CHECK_EQ(detector.busiest()->target, std::string("198.51.100.20")); // the screen stays on the port scan
}

TEST(floodOfForgedAddressesStaysWithinTheCap)
{
	// 10,000 SYNs from 10,000 forged addresses: each would be a new pair and a new sweep
	ScanDetector detector(20, 10 * SECOND, 20, 64);
	for (int i = 0; i < 10'000; ++i)
	{
		detector.observe(tcp(forged(i), TARGET, 40000, 80, tcp_flag::SYN), i);
	}
	CHECK_EQ(detector.tracked(), std::size_t{64});
	CHECK_EQ(detector.dropped(), std::size_t{2 * (10'000 - 64)}); // pairs and sweeps
}

TEST(floodNeverDropsTheScanOnScreen)
{
	ScanDetector detector(20, 10 * SECOND, 20, 64);
	for (std::uint16_t port = 1; port <= 30; ++port)
	{
		detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), port);
	}
	for (int i = 0; i < 5'000; ++i)
	{
		detector.observe(tcp(forged(i), TARGET, 40000, 80, tcp_flag::SYN), 100 + i);
	}
	const ScanTrack* track = detector.busiest();
	CHECK(track != nullptr);
	CHECK_EQ(track->source, std::string("203.0.113.7"));
	CHECK_EQ(track->ports.size(), std::size_t{30});

	// its answers still arrive at it after the flood
	detector.observe(tcp(TARGET, SCANNER, 22, 40000, tcp_flag::SYN | tcp_flag::ACK), 6'000);
	CHECK(detector.busiest()->ports.at(22) == PortState::Open);
}

TEST(floodCannotHideARealScan)
{
	// a real scan interleaved with a flood: the real pair is touched on every probe, so it is
	// never the least recent and is never dropped; it still reaches the threshold
	ScanDetector detector(20, 10 * SECOND, 20, 64);
	bool alerted = false;
	for (int i = 0; i < 2'000; ++i)
	{
		detector.observe(tcp(forged(i), TARGET, 40000, 80, tcp_flag::SYN), i * 10);
		if (i % 50 == 0)
		{
			const auto port = static_cast<std::uint16_t>(1 + i / 50);
			alerted = detector.observe(tcp(SCANNER, TARGET, 40000, port, tcp_flag::SYN), i * 10 + 1).has_value() || alerted;
		}
	}
	CHECK(alerted);
}

TEST(forgedAnswersCreateNothing)
{
	// SYN-ACKs and RSTs only update scans already being followed; they never add entries
	ScanDetector detector(20, 10 * SECOND, 20, 64);
	for (int i = 0; i < 1'000; ++i)
	{
		detector.observe(tcp(forged(i), TARGET, 80, 40000, tcp_flag::RST), i);
		detector.observe(tcp(forged(i), TARGET, 80, 40000, tcp_flag::SYN | tcp_flag::ACK), i);
	}
	CHECK_EQ(detector.tracked(), std::size_t{0});
	CHECK_EQ(detector.dropped(), std::size_t{0});
}

TEST(watchFrameShowsSweepAndDrops)
{
	ScanDetector detector(20, 10 * SECOND, 3, 64);
	std::optional<ScanAlert> sweep;
	for (int host = 1; host <= 3; ++host)
	{
		sweep = detector.observe(sshProbe(host), host);
	}
	WatchStatus status;
	status.sourceLabel = "LIVE";
	status.packets = 3;
	status.nowMicros = 3;
	status.sweep = sweep;
	// a port scan banner too, with long numbers, so the widest realistic banners are measured
	status.alert = ScanAlert{.kind = ScanKind::PortScan, .source = "203.0.113.107", .target = "198.51.100.120",
		.ports = 65535, .elapsedMicros = 125 * SECOND};
	status.tracked = 64;
	status.dropped = 12'345;
	const std::string frame = visible(renderWatch(detector.busiest(), status, 0));
	CHECK_EQ(static_cast<int>(std::count(frame.begin(), frame.end(), '\n')), WATCH_LINES);
	CHECK(frame.find("PORT SCAN DETECTED") != std::string::npos);
	CHECK(frame.find("HOST SWEEP") != std::string::npos);
	CHECK(frame.find("198.51.100.0/24") != std::string::npos);
	CHECK(frame.find("port 22 ssh") != std::string::npos);
	CHECK(frame.find("12,345 dropped") != std::string::npos);

	// every line is at most 78 columns, so nothing wraps and the frame keeps its height
	std::size_t start = 0;
	for (int line = 0; line < WATCH_LINES; ++line)
	{
		const std::size_t end = frame.find('\n', start);
		const std::string text = frame.substr(start, end - start);
		const auto columns = std::count_if(text.begin(), text.end(),
			[](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; });
		CHECK(columns <= std::ptrdiff_t{78});
		start = end + 1;
	}
}
