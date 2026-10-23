#include "fixtures.hpp"
#include "packet.hpp"

using namespace wiresight;

/** WHAT: Ethernet addresses and EtherType of a normal frame. WHY: every other layer starts here. */
TEST(ethernetHeader)
{
	const auto frame = fixtures::tcpSyn();
	const auto eth = parseEthernet(frame);
	CHECK(eth.has_value());
	CHECK_EQ(toString(eth->destination), std::string("00:11:22:33:44:55"));
	CHECK_EQ(toString(eth->source), std::string("66:77:88:99:aa:bb"));
	CHECK_EQ(eth->etherType, ETHERTYPE_IPV4);
	CHECK_EQ(eth->headerLength, 14u);
	CHECK(!eth->vlanId.has_value());
}

/** WHAT: an 802.1Q tagged frame. WHY: the real EtherType sits after the 4-byte tag. */
TEST(ethernetVlanTag)
{
	auto frame = fixtures::tcpSyn();
	const auto tag = test::hex("81 00 00 64"); // VLAN 100
	frame.insert(frame.begin() + 12, tag.begin(), tag.end());
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.ethernet.has_value());
	CHECK_EQ(*packet.ethernet->vlanId, 100);
	CHECK_EQ(packet.ethernet->etherType, ETHERTYPE_IPV4);
	CHECK(packet.tcp.has_value());
}

/** WHAT: an ARP request. WHY: how a PC finds its router; also what ARP spoofing forges. */
TEST(arpRequest)
{
	const auto frame = fixtures::arpRequest();
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.arp.has_value());
	CHECK_EQ(packet.arp->operation, ARP_REQUEST);
	CHECK_EQ(toString(packet.arp->senderIp), std::string("192.168.1.5"));
	CHECK_EQ(toString(packet.arp->targetIp), std::string("192.168.1.1"));
	CHECK(!packet.ipv4.has_value());
}

/** WHAT: loopback capture (DLT 0). WHY: this is how 127.0.0.1 traffic, e.g. portscout's, arrives. */
TEST(loopbackNullHeader)
{
	const auto frame = fixtures::tcpSyn();
	std::vector<std::uint8_t> loopback = test::hex("02 00 00 00"); // AF_INET in little-endian
	loopback.insert(loopback.end(), frame.begin() + 14, frame.end());
	const DecodedPacket packet = decode(loopback, LinkType::Null, loopback.size());
	CHECK(!packet.ethernet.has_value());
	CHECK(packet.ipv4.has_value());
	CHECK(packet.tcp.has_value());
	CHECK_EQ(packet.tcp->destinationPort, 443);
}

/** WHAT: the DLT numbers libpcap reports. WHY: picking the wrong one would misread every packet. */
TEST(linkTypeMapping)
{
	CHECK(linkTypeFromDlt(1) == LinkType::Ethernet);
	CHECK(linkTypeFromDlt(0) == LinkType::Null);
	CHECK(linkTypeFromDlt(101) == LinkType::Raw);
	CHECK(linkTypeFromDlt(12) == LinkType::Raw);
	CHECK(linkTypeFromDlt(127) == LinkType::Unknown); // 802.11 radiotap
}

/** WHAT: MAC formatting. WHY: lowercase with colons, two digits per byte. */
TEST(macFormatting)
{
	CHECK_EQ(toString(MacAddress{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}), std::string("00:1a:2b:3c:4d:5e"));
}
