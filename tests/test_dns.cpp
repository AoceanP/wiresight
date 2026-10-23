#include "fixtures.hpp"
#include "packet.hpp"

using namespace wiresight;

/** WHAT: a DNS query inside a full frame. WHY: UDP port 53 must trigger DNS decoding. */
TEST(dnsQuery)
{
	const auto frame = fixtures::dnsQuery();
	const DecodedPacket packet = decode(frame, LinkType::Ethernet, frame.size());
	CHECK(packet.dns.has_value());
	CHECK(!packet.dns->isResponse);
	CHECK_EQ(packet.dns->id, 0x1a2b);
	CHECK_EQ(packet.dns->questions.size(), 1u);
	CHECK_EQ(packet.dns->questions[0].name, std::string("example.com"));
	CHECK_EQ(dnsTypeName(packet.dns->questions[0].type), std::string("A"));
}

/** WHAT: a response whose answer name is a compression pointer. WHY: almost every real response uses one. */
TEST(dnsResponseWithPointer)
{
	const auto message = fixtures::dnsResponse();
	const auto dns = parseDns(message);
	CHECK(dns.has_value());
	CHECK(dns->isResponse);
	CHECK(!dns->malformed);
	CHECK_EQ(dnsRcodeName(dns->rcode), std::string("NOERROR"));
	CHECK_EQ(dns->answers.size(), 1u);
	CHECK_EQ(dns->answers[0].name, std::string("example.com"));
	CHECK_EQ(dns->answers[0].data, std::string("93.184.216.34"));
	CHECK_EQ(dns->answers[0].ttl, 3600u);
}

/** WHAT: a CNAME then an A record, both compressed. WHY: CDNs answer this way; the CNAME data is itself a pointer. */
TEST(dnsCnameChain)
{
	const auto message = test::hex(
		"ab cd 81 80 00 01 00 02 00 00 00 00"
		"03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00  00 01 00 01" // www.example.com A
		"c0 0c 00 05 00 01 00 00 01 2c 00 02 c0 10"                        // CNAME -> pointer to "example.com"
		"c0 10 00 01 00 01 00 00 01 2c 00 04 5d b8 d8 22");                // example.com A
	const auto dns = parseDns(message);
	CHECK(dns.has_value());
	CHECK(!dns->malformed);
	CHECK_EQ(dns->answers.size(), 2u);
	CHECK_EQ(dns->answers[0].name, std::string("www.example.com"));
	CHECK_EQ(dnsTypeName(dns->answers[0].type), std::string("CNAME"));
	CHECK_EQ(dns->answers[0].data, std::string("example.com"));
	CHECK_EQ(dns->answers[1].data, std::string("93.184.216.34"));
}

/** WHAT: an NXDOMAIN response. WHY: "no such name" is what people look for when a site will not load. */
TEST(dnsNxdomain)
{
	const auto dns = parseDns(test::hex("1a 2b 81 83 00 00 00 00 00 00 00 00"));
	CHECK(dns.has_value());
	CHECK_EQ(dnsRcodeName(dns->rcode), std::string("NXDOMAIN"));
}

/** WHAT: AAAA answer data. WHY: IPv6 answers must use the short address form. */
TEST(dnsAaaaAnswer)
{
	const auto message = test::hex(
		"00 01 81 80 00 01 00 01 00 00 00 00"
		"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00  00 1c 00 01"
		"c0 0c 00 1c 00 01 00 00 00 3c 00 10  26 06 28 00 02 20 00 01 02 48 18 93 25 c8 19 46");
	const auto dns = parseDns(message);
	CHECK(dns.has_value());
	CHECK_EQ(dns->answers.size(), 1u);
	CHECK_EQ(dns->answers[0].data, std::string("2606:2800:220:1:248:1893:25c8:1946"));
}

/** WHAT: record type and rcode names. WHY: unknown numbers must still print something useful. */
TEST(dnsNames)
{
	CHECK_EQ(dnsTypeName(28), std::string("AAAA"));
	CHECK_EQ(dnsTypeName(65), std::string("HTTPS"));
	CHECK_EQ(dnsTypeName(999), std::string("TYPE999"));
	CHECK_EQ(dnsRcodeName(2), std::string("SERVFAIL"));
	CHECK_EQ(dnsRcodeName(9), std::string("RCODE9"));
}
