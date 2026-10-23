#include "fixtures.hpp"
#include "format.hpp"
#include "packet.hpp"

#include <algorithm>

using namespace wiresight;

/**
 * WHAT:   Edge cases, each listed in the README's "Edge cases" table.
 * WHY:    Packet decoders read data from strangers; short, malformed and
 *         hostile input is where real sniffers (including Wireshark) have
 *         had security bugs. None of these may crash or read out of bounds.
 */

namespace
{

/**
 * WHAT:   Tells whether any note contains a piece of text.
 * WHY:    Notes explain what went wrong; tests check the right one appears.
 * RETURN: true if a note contains piece
 *
 * @param packet the decoded packet
 * @param piece  the text to look for
 * @return whether a matching note exists
 */
bool hasNote(const DecodedPacket& packet, const std::string& piece)
{
	return std::any_of(packet.notes.begin(), packet.notes.end(),
		[&](const std::string& note) { return note.find(piece) != std::string::npos; });
}

} // namespace

/** WHAT: a frame cut at every possible length. WHY: no prefix of a real packet may crash the decoder. */
TEST(everyTruncationIsSafe)
{
	for (const auto& frame : {fixtures::tcpSyn(), fixtures::dnsQuery(), fixtures::arpRequest()})
	{
		for (std::size_t length = 0; length <= frame.size(); ++length)
		{
			const Bytes cut = Bytes(frame).first(length);
			const DecodedPacket packet = decode(cut, LinkType::Ethernet, frame.size());
			const std::string line = summarize(packet); // must not throw or read past the end
			CHECK(!line.empty());
			if (length < frame.size())
			{
				CHECK(hasNote(packet, "bytes captured"));
			}
		}
	}
}

/** WHAT: an empty capture. WHY: zero bytes is still a valid input. */
TEST(emptyFrame)
{
	const DecodedPacket packet = decode(Bytes(), LinkType::Ethernet, 0);
	CHECK(!packet.ethernet.has_value());
	CHECK(hasNote(packet, "Ethernet header incomplete"));
}

/** WHAT: an IPv4 header length below 20 (IHL 4). WHY: impossible; trusting it would treat header bytes as data. */
TEST(ipv4HeaderLengthTooSmall)
{
	auto frame = fixtures::tcpSyn();
	frame[14] = 0x44;
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(!packet.ipv4.has_value());
	CHECK(hasNote(packet, "IPv4 header incomplete or invalid"));
}

/** WHAT: an IPv4 total length below the header length. WHY: a lie in the length field must be refused. */
TEST(ipv4TotalLengthTooSmall)
{
	auto frame = fixtures::tcpSyn();
	frame[16] = 0x00;
	frame[17] = 0x10; // total length 16 < header 20
	CHECK(!parseIpv4(Bytes(frame).subspan(14)).has_value());
}

/** WHAT: a TCP data offset pointing past the captured bytes. WHY: 15 x 4 = 60 bytes claimed, only 24 there. */
TEST(tcpHeaderLengthPastEnd)
{
	auto frame = fixtures::tcpSyn();
	frame[14 + 20 + 12] = 0xF0;
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(!packet.tcp.has_value());
	CHECK(hasNote(packet, "TCP header incomplete"));
}

/** WHAT: a UDP length field below 8. WHY: shorter than its own header, so it must be refused. */
TEST(udpLengthTooSmall)
{
	CHECK(!parseUdp(test::hex("00 35 d4 31 00 04 00 00")).has_value());
}

/** WHAT: a later IPv4 fragment. WHY: only the first fragment has the TCP header; the rest is data. */
TEST(ipv4LaterFragment)
{
	auto frame = fixtures::tcpSyn();
	frame[14 + 6] = 0x00;
	frame[14 + 7] = 0x10; // fragment offset 16 x 8 = 128 bytes
	test::fixIpv4Checksum(frame, 14);
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.ipv4.has_value());
	CHECK_EQ(packet.ipv4->fragmentOffset, 128u);
	CHECK(!packet.tcp.has_value());
	CHECK(hasNote(packet, "IPv4 fragment at offset 128"));
}

/** WHAT: Ethernet padding after a tiny UDP packet. WHY: frames are padded to 60 bytes; padding is not data. */
TEST(ethernetPaddingIgnored)
{
	auto frame = test::hex(
		"00 11 22 33 44 55  66 77 88 99 aa bb  08 00"
		"45 00 00 20 00 03 00 00 40 11 00 00 0a 00 00 01 0a 00 00 02"
		"30 39 30 3a 00 0c 00 00  de ad be ef"
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00"); // padding to 60 bytes
	test::fixIpv4Checksum(frame, 14);
	CHECK_EQ(frame.size(), 60u);
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.udp.has_value());
	CHECK_EQ(packet.udp->payload.size(), 4u);
}

/** WHAT: an 802.3 frame with a length instead of an EtherType. WHY: switches send these (spanning tree). */
TEST(ethernet8023LengthFrame)
{
	const auto frame = test::hex("01 80 c2 00 00 00  66 77 88 99 aa bb  00 26  42 42 03 00 00 00");
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.ethernet.has_value());
	CHECK(packet.ethernet->isLengthField());
	CHECK(summarize(packet).starts_with("802.3"));
}

/** WHAT: an EtherType this program does not decode (LLDP). WHY: it is shown by number, not dropped or misread. */
TEST(unknownEtherType)
{
	const auto frame = test::hex("01 80 c2 00 00 0e  66 77 88 99 aa bb  88 cc  02 07 04");
	const std::string line = summarize(decode(frame, LinkType::Ethernet, frame.size()));
	CHECK(line.find("type 0x88cc") != std::string::npos);
}

/** WHAT: a DNS name that points at itself. WHY: the classic way to hang a DNS parser forever. */
TEST(dnsPointerLoop)
{
	const auto dns = parseDns(test::hex("00 01 00 00 00 01 00 00 00 00 00 00  c0 0c 00 01 00 01"));
	CHECK(dns.has_value());
	CHECK(dns->malformed);
	CHECK(dns->questions.empty());
}

/** WHAT: two pointers pointing at each other. WHY: a loop of length 2 must be stopped too. */
TEST(dnsPointerCycle)
{
	const auto dns = parseDns(test::hex("00 01 00 00 00 01 00 00 00 00 00 00  c0 0e c0 0c"));
	CHECK(dns.has_value());
	CHECK(dns->malformed);
}

/** WHAT: a pointer past the end of the message. WHY: following it would read memory that is not the packet. */
TEST(dnsPointerOutOfRange)
{
	const auto dns = parseDns(test::hex("00 01 00 00 00 01 00 00 00 00 00 00  c3 ff 00 01 00 01"));
	CHECK(dns.has_value());
	CHECK(dns->malformed);
}

/** WHAT: a label longer than the bytes left. WHY: the length byte is attacker-controlled. */
TEST(dnsLabelPastEnd)
{
	const auto dns = parseDns(test::hex("00 01 00 00 00 01 00 00 00 00 00 00  3f 61 62 63"));
	CHECK(dns.has_value());
	CHECK(dns->malformed);
}

/** WHAT: a name longer than 255 bytes. WHY: RFC 1035's limit; longer names are invalid and could exhaust memory. */
TEST(dnsNameTooLong)
{
	std::vector<std::uint8_t> message = test::hex("00 01 00 00 00 01 00 00 00 00 00 00");
	for (int i = 0; i < 5; ++i) // 5 labels of 63 bytes = 320 bytes
	{
		message.push_back(63);
		message.insert(message.end(), 63, 'a');
	}
	message.push_back(0);
	message.insert(message.end(), {0, 1, 0, 1});
	const auto dns = parseDns(message);
	CHECK(dns.has_value());
	CHECK(dns->malformed);
}

/** WHAT: a header claiming 65,535 questions in a tiny message. WHY: counts are attacker-controlled; must stop quickly. */
TEST(dnsHugeQuestionCount)
{
	const auto dns = parseDns(test::hex("00 01 00 00 ff ff 00 00 00 00 00 00"));
	CHECK(dns.has_value());
	CHECK(dns->malformed);
}

/** WHAT: control characters and a dot inside a label. WHY: names are remote data; they must not reach the terminal raw. */
TEST(dnsUnprintableLabel)
{
	const auto dns = parseDns(test::hex("00 01 00 00 00 01 00 00 00 00 00 00  04 61 1b 2e 62 00 00 01 00 01"));
	CHECK(dns.has_value());
	CHECK(!dns->malformed);
	CHECK_EQ(dns->questions[0].name, std::string("a??b"));
}

/** WHAT: the root name. WHY: an empty name is legal (e.g. root NS queries) and is shown as ".". */
TEST(dnsRootName)
{
	const auto dns = parseDns(test::hex("00 01 00 00 00 01 00 00 00 00 00 00  00 00 02 00 01"));
	CHECK(dns.has_value());
	CHECK_EQ(dns->questions[0].name, std::string("."));
}

/** WHAT: an answer whose data length runs past the end. WHY: rdlength is attacker-controlled. */
TEST(dnsAnswerDataPastEnd)
{
	auto message = fixtures::dnsResponse();
	message[message.size() - 5] = 0x40; // rdlength 4 -> 64, with only 4 bytes left
	const auto dns = parseDns(message);
	CHECK(dns.has_value());
	CHECK(dns->malformed);
	CHECK(dns->answers.empty());
}

/** WHAT: an IPv6 extension header whose length runs past the end. WHY: the walk must stop, not read on. */
TEST(ipv6ExtensionPastEnd)
{
	auto ip = fixtures::ipv6PingWithHopByHop();
	ip[41] = 0xFF; // hop-by-hop length: (255 + 1) x 8 = 2048 bytes
	const auto parsed = parseIpv6(ip);
	CHECK(parsed.has_value());
	CHECK(parsed->extensionHeaders.empty());
	CHECK_EQ(static_cast<int>(parsed->upperProtocol), 0);
}

/** WHAT: a link type this program does not know. WHY: it says so instead of guessing. */
TEST(unknownLinkType)
{
	const auto frame = fixtures::tcpSyn();
	const DecodedPacket packet = decode(frame, LinkType::Unknown, frame.size());
	CHECK(hasNote(packet, "link type not supported"));
	CHECK(summarize(packet).find("58 bytes") != std::string::npos);
}
