#pragma once

#include "bytes.hpp"

#include <optional>
#include <string>
#include <vector>

namespace wiresight
{

/** WHAT: one question from a DNS message, e.g. "example.com, type A". */
struct DnsQuestion
{
	/** WHAT: the name being looked up, dot-separated. */
	std::string name;
	/** WHAT: record type asked for (1 A, 28 AAAA...). */
	std::uint16_t type = 0;
	/** WHAT: record class, almost always 1 (internet). */
	std::uint16_t recordClass = 0;
};

/** WHAT: one answer record from a DNS response. */
struct DnsAnswer
{
	/** WHAT: the name this record is for. */
	std::string name;
	/** WHAT: record type (1 A, 5 CNAME, 28 AAAA...). */
	std::uint16_t type = 0;
	/** WHAT: seconds the answer may be cached. */
	std::uint32_t ttl = 0;
	/** WHAT: the answer as text: an address, a name, or "<N bytes>". */
	std::string data;
};

/**
 * WHAT:   A DNS query or response.
 * WHY:    DNS shows which sites a machine visits before any connection is
 *         made, so it is one of the most useful things to see on a network,
 *         for troubleshooting and for spotting malware calling home.
 */
struct DnsMessage
{
	/** WHAT: matches a response to its query. */
	std::uint16_t id = 0;
	/** WHAT: false for a query, true for a response. */
	bool isResponse = false;
	/** WHAT: 0 for a standard query. */
	std::uint8_t opcode = 0;
	/** WHAT: result code of a response (0 NOERROR, 3 NXDOMAIN...). */
	std::uint8_t rcode = 0;
	/** WHAT: number of questions the header announces. */
	std::uint16_t questionCount = 0;
	/** WHAT: number of answers the header announces. */
	std::uint16_t answerCount = 0;
	/** WHAT: the questions that were decoded. */
	std::vector<DnsQuestion> questions;
	/** WHAT: the answers that were decoded (at most 32). */
	std::vector<DnsAnswer> answers;
	/** WHAT: decoding stopped early because the message was cut short or invalid. */
	bool malformed = false;
};

/**
 * WHAT:   Decodes a DNS message, including compressed names.
 * WHY:    Names may point to earlier names (compression). Pointer jumps are
 *         capped at 16 and names at 255 bytes, so a crafted message that
 *         points at itself cannot hang the decoder, a classic parser bug.
 * PRE:    message starts at the DNS header (the UDP payload)
 * RETURN: the message, or nothing if it is shorter than the 12-byte header;
 *         malformed is set when only part of it could be read
 *
 * @param message the DNS bytes
 * @return the decoded message, or std::nullopt
 */
std::optional<DnsMessage> parseDns(Bytes message);

/**
 * WHAT:   Names a DNS record type, e.g. 28 becomes "AAAA".
 * WHY:    Record types are shown in every DNS summary line.
 * RETURN: the name, or "TYPE<n>" for unknown types (the RFC 3597 style)
 *
 * @param type the record type number
 * @return the readable name
 */
std::string dnsTypeName(std::uint16_t type);

/**
 * WHAT:   Names a DNS response code, e.g. 3 becomes "NXDOMAIN".
 * WHY:    NXDOMAIN (no such name) and SERVFAIL are the answers people look for.
 * RETURN: the name, or "RCODE<n>" for unknown codes
 *
 * @param rcode the response code
 * @return the readable name
 */
std::string dnsRcodeName(std::uint8_t rcode);

} // namespace wiresight
