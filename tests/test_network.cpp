#include "fixtures.hpp"
#include "packet.hpp"

using namespace wiresight;

/** WHAT: the IPv4 fields of a TCP SYN. WHY: addresses, TTL and flags drive every summary. */
TEST(ipv4Header)
{
	const auto frame = fixtures::tcpSyn();
	const auto ip = parseIpv4(Bytes(frame).subspan(14));
	CHECK(ip.has_value());
	CHECK_EQ(toString(ip->source), std::string("192.168.1.5"));
	CHECK_EQ(toString(ip->destination), std::string("93.184.216.34"));
	CHECK_EQ(static_cast<int>(ip->ttl), 64);
	CHECK_EQ(static_cast<int>(ip->protocol), static_cast<int>(PROTOCOL_TCP));
	CHECK(ip->dontFragment);
	CHECK(!ip->moreFragments);
	CHECK_EQ(ip->headerLength, 20u);
	CHECK_EQ(ip->payload.size(), 24u);
	CHECK(ip->checksumValid);
}

/** WHAT: the checksum example from Wikipedia's IPv4 article. WHY: a known-good answer (0xb861). */
TEST(ipv4ChecksumKnownExample)
{
	auto header = test::hex("45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7");
	CHECK_EQ(internetChecksum(header), 0);
	header[15] ^= 0x01; // flip one bit in the source address
	CHECK(internetChecksum(header) != 0);
}

/** WHAT: a header with 4 bytes of options (IHL 6). WHY: the payload must start after the options. */
TEST(ipv4WithOptions)
{
	auto ip = test::hex("46 00 00 20 00 00 00 00 40 11 00 00 0a 00 00 01 0a 00 00 02  01 01 01 00  30 39 30 3a 00 08 00 00");
	test::fixIpv4Checksum(ip, 0);
	const DecodedPacket packet = decode(ip, LinkType::Raw, ip.size());
	CHECK(packet.ipv4.has_value());
	CHECK_EQ(packet.ipv4->headerLength, 24u);
	CHECK(packet.udp.has_value());
	CHECK_EQ(packet.udp->sourcePort, 12345);
}

/** WHAT: IPv6 behind a hop-by-hop header, carrying a ping. WHY: the real protocol hides behind extension headers. */
TEST(ipv6WithExtensionHeader)
{
	const auto ip = fixtures::ipv6PingWithHopByHop();
	const DecodedPacket packet = decode(ip, LinkType::Raw, ip.size());
	CHECK(packet.ipv6.has_value());
	CHECK_EQ(toString(packet.ipv6->source), std::string("fe80::1"));
	CHECK_EQ(toString(packet.ipv6->destination), std::string("ff02::1"));
	CHECK_EQ(packet.ipv6->extensionHeaders.size(), 1u);
	CHECK_EQ(static_cast<int>(packet.ipv6->upperProtocol), 58);
	CHECK(packet.icmp.has_value());
	CHECK(packet.icmp->version6);
	CHECK_EQ(describeIcmp(*packet.icmp), std::string("echo request id=1 seq=2"));
}

/** WHAT: RFC 5952 short forms. WHY: only runs of 2+ zero groups become "::", and the longest one wins. */
TEST(ipv6Formatting)
{
	Ipv6Address loopback{};
	loopback[15] = 1;
	CHECK_EQ(toString(loopback), std::string("::1"));
	CHECK_EQ(toString(Ipv6Address{}), std::string("::"));

	const auto doc = test::hex("20 01 0d b8 00 00 00 01 00 01 00 01 00 01 00 01");
	CHECK_EQ(toString(readArray<16>(doc, 0)), std::string("2001:db8:0:1:1:1:1:1")); // single zero group stays

	const auto twoRuns = test::hex("20 01 0d b8 00 00 00 00 00 01 00 00 00 00 00 00");
	CHECK_EQ(toString(readArray<16>(twoRuns, 0)), std::string("2001:db8:0:0:1::")); // longer run wins
}
