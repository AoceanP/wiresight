#include "fixtures.hpp"
#include "packet.hpp"

using namespace wiresight;

/** WHAT: the TCP fields of a SYN with an MSS option. WHY: header length 24 must skip the option. */
TEST(tcpSyn)
{
	const auto frame = fixtures::tcpSyn();
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.tcp.has_value());
	CHECK_EQ(packet.tcp->sourcePort, 51256);
	CHECK_EQ(packet.tcp->destinationPort, 443);
	CHECK_EQ(packet.tcp->sequence, 100u);
	CHECK_EQ(packet.tcp->headerLength, 24u);
	CHECK_EQ(static_cast<int>(packet.tcp->flags), static_cast<int>(tcp_flag::SYN));
	CHECK_EQ(packet.tcp->window, 64240);
	CHECK_EQ(packet.tcp->payload.size(), 0u);
	CHECK(packet.notes.empty());
}

/** WHAT: flag names. WHY: portscout's three answers are SYN-ACK (open) and RST (closed). */
TEST(tcpFlagNames)
{
	CHECK_EQ(tcpFlagsToString(tcp_flag::SYN | tcp_flag::ACK), std::string("SYN, ACK"));
	CHECK_EQ(tcpFlagsToString(tcp_flag::RST | tcp_flag::ACK), std::string("RST, ACK"));
	CHECK_EQ(tcpFlagsToString(tcp_flag::FIN | tcp_flag::PSH | tcp_flag::ACK), std::string("FIN, PSH, ACK"));
	CHECK_EQ(tcpFlagsToString(0), std::string("none"));
}

/** WHAT: a UDP header. WHY: the length field decides where the data ends. */
TEST(udpHeader)
{
	const auto frame = fixtures::dnsQuery();
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.udp.has_value());
	CHECK_EQ(packet.udp->sourcePort, 54321);
	CHECK_EQ(packet.udp->destinationPort, 53);
	CHECK_EQ(packet.udp->length, 37);
	CHECK_EQ(packet.udp->payload.size(), 29u);
}

/** WHAT: ICMP messages by type and code. WHY: "port unreachable" is how a closed UDP port answers. */
TEST(icmpDescriptions)
{
	CHECK_EQ(describeIcmp(*parseIcmp(test::hex("08 00 00 00 00 07 00 03"), false)), std::string("echo request id=7 seq=3"));
	CHECK_EQ(describeIcmp(*parseIcmp(test::hex("03 03 00 00"), false)), std::string("destination unreachable (port)"));
	CHECK_EQ(describeIcmp(*parseIcmp(test::hex("0b 00 00 00"), false)), std::string("time exceeded"));
	CHECK_EQ(describeIcmp(*parseIcmp(test::hex("87 00 00 00"), true)), std::string("neighbor solicitation"));
	CHECK_EQ(describeIcmp(*parseIcmp(test::hex("2a 01 00 00"), false)), std::string("type 42 code 1"));
}
