#include "fixtures.hpp"
#include "format.hpp"

using namespace wiresight;

namespace
{

/**
 * WHAT:   Tells whether text contains a piece.
 * WHY:    Summary lines have padding; tests check content, not spacing.
 * RETURN: true if piece is in text
 *
 * @param text  the full text
 * @param piece the part to look for
 * @return whether piece was found
 */
bool contains(const std::string& text, const std::string& piece)
{
	return text.find(piece) != std::string::npos;
}

} // namespace

/** WHAT: the summary of a TCP SYN. WHY: the line people read most. */
TEST(summaryTcp)
{
	const auto frame = fixtures::tcpSyn();
	const std::string line = summarize(decode(frame, LinkType::Ethernet, frame.size()));
	CHECK(line.starts_with("TCP"));
	CHECK(contains(line, "192.168.1.5:51256 -> 93.184.216.34:443"));
	CHECK(contains(line, "[SYN] seq=100 len=0"));
	CHECK(!contains(line, "ack="));
	CHECK(!contains(line, "!"));
}

/** WHAT: the summary of a DNS query. WHY: DNS is shown instead of plain UDP. */
TEST(summaryDns)
{
	const auto frame = fixtures::dnsQuery();
	const std::string line = summarize(decode(frame, LinkType::Ethernet, frame.size()));
	CHECK(line.starts_with("DNS"));
	CHECK(contains(line, "192.168.1.5:54321 -> 1.1.1.1:53"));
	CHECK(contains(line, "query 0x1a2b A example.com"));
}

/** WHAT: the summary of an ARP request. WHY: read the way tcpdump says it. */
TEST(summaryArp)
{
	const auto frame = fixtures::arpRequest();
	const std::string line = summarize(decode(frame, LinkType::Ethernet, frame.size()));
	CHECK(contains(line, "who has 192.168.1.1? tell 192.168.1.5"));
}

/** WHAT: an IPv6 address next to a port. WHY: brackets keep the port apart from the address's own colons. */
TEST(summaryIpv6Brackets)
{
	auto ip = test::hex(
		"60 00 00 00 00 08 11 40"
		"fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 01"
		"fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 02"
		"30 39 00 50 00 08 00 00");
	const std::string line = summarize(decode(ip, LinkType::Raw, ip.size()));
	CHECK(contains(line, "[fe80::1]:12345 -> [fe80::2]:80"));
}

/** WHAT: notes at the end of the summary. WHY: problems must be visible without -v. */
TEST(summaryShowsNotes)
{
	auto frame = fixtures::tcpSyn();
	frame[14 + 11] ^= 0xFF; // break the IPv4 checksum
	const std::string line = summarize(decode(frame, LinkType::Ethernet, frame.size() + 100));
	CHECK(contains(line, "! only 58 of 158 bytes captured"));
	CHECK(contains(line, "IPv4 checksum mismatch"));
}

/** WHAT: verbose layer lines. WHY: -v must show every decoded layer once. */
TEST(verboseLayers)
{
	const auto frame = fixtures::tcpSyn();
	const std::string text = describeLayers(decode(frame, LinkType::Ethernet, frame.size()));
	CHECK(contains(text, "Ethernet"));
	CHECK(contains(text, "ttl 64"));
	CHECK(contains(text, "checksum ok"));
	CHECK(contains(text, "window 64240"));
	CHECK(contains(text, "header 24 B"));
}

/** WHAT: timestamp fraction. WHY: microseconds keep 6 digits; the hour depends on the local time zone, so only the end is checked. */
TEST(timestampMicroseconds)
{
	CHECK(formatTimestamp(0, 5).ends_with(".000005"));
	CHECK(formatTimestamp(0, 123456).ends_with(".123456"));
	CHECK_EQ(formatTimestamp(0, 0).size(), 15u);
}
