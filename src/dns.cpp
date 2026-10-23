#include "dns.hpp"

#include <format>

namespace wiresight
{

namespace
{

constexpr std::size_t HEADER_LENGTH = 12;
constexpr int MAX_POINTER_JUMPS = 16;
constexpr std::size_t MAX_NAME_LENGTH = 255;
constexpr std::size_t MAX_QUESTIONS = 16;
constexpr std::size_t MAX_ANSWERS = 32;

constexpr std::uint16_t TYPE_A = 1;
constexpr std::uint16_t TYPE_NS = 2;
constexpr std::uint16_t TYPE_CNAME = 5;
constexpr std::uint16_t TYPE_PTR = 12;
constexpr std::uint16_t TYPE_AAAA = 28;

/**
 * WHAT:   Reads a possibly compressed domain name.
 * WHY:    A name is a list of length-prefixed labels ending in 0, or a
 *         2-byte pointer (top bits 11) to a name elsewhere in the message.
 * PRE:    offset is inside message
 * POST:   name holds the dotted name, with unprintable bytes shown as '?'
 * RETURN: the offset just after the name where it first appeared (after
 *         the first pointer, not the end of the pointed-to name), or
 *         nothing if the name runs past the end, loops, or is too long
 *
 * @param message the whole DNS message (pointers are relative to its start)
 * @param offset  where the name starts
 * @param name    receives the decoded name
 * @return the offset after the name, or std::nullopt if it is invalid
 */
std::optional<std::size_t> readName(Bytes message, std::size_t offset, std::string& name)
{
	name.clear();
	std::size_t position = offset;
	std::optional<std::size_t> resumeAt;
	std::size_t wireLength = 0;
	int jumps = 0;

	while (true)
	{
		if (position >= message.size())
		{
			return std::nullopt;
		}
		const std::uint8_t length = message[position];

		if (length == 0)
		{
			if (!resumeAt)
			{
				resumeAt = position + 1;
			}
			break;
		}

		if ((length & 0xC0) == 0xC0)
		{
			if (position + 1 >= message.size())
			{
				return std::nullopt;
			}
			if (!resumeAt)
			{
				resumeAt = position + 2;
			}
			// a pointer to itself, or a chain of pointers, would loop forever without this cap
			if (++jumps > MAX_POINTER_JUMPS)
			{
				return std::nullopt;
			}
			position = static_cast<std::size_t>(length & 0x3F) << 8 | message[position + 1];
			continue;
		}

		// label types 01 and 10 are reserved and never valid
		if ((length & 0xC0) != 0 || position + 1 + length > message.size())
		{
			return std::nullopt;
		}
		wireLength += 1u + length;
		if (wireLength > MAX_NAME_LENGTH)
		{
			return std::nullopt;
		}

		if (!name.empty())
		{
			name += '.';
		}
		for (std::size_t i = 0; i < length; ++i)
		{
			const std::uint8_t c = message[position + 1 + i];
			// names are remote data; keep control characters and dots-inside-labels out of the output
			name += (c >= 0x21 && c <= 0x7E && c != '.') ? static_cast<char>(c) : '?';
		}
		position += 1u + length;
	}

	if (name.empty())
	{
		name = ".";
	}
	return resumeAt;
}

/**
 * WHAT:   Turns the data of one answer record into text.
 * WHY:    A, AAAA and name records are worth showing; anything else is
 *         summarised by size so binary data never reaches the terminal.
 * PRE:    rdataOffset + rdataLength <= message.size()
 * RETURN: the address or name, or "<N bytes>"
 *
 * @param message     the whole DNS message
 * @param type        the record type
 * @param rdataOffset where the record data starts
 * @param rdataLength how long the record data is
 * @return the record data as text
 */
std::string answerData(Bytes message, std::uint16_t type, std::size_t rdataOffset, std::size_t rdataLength)
{
	if (type == TYPE_A && rdataLength == 4)
	{
		return toString(readArray<4>(message, rdataOffset));
	}
	if (type == TYPE_AAAA && rdataLength == 16)
	{
		return toString(readArray<16>(message, rdataOffset));
	}
	if (type == TYPE_CNAME || type == TYPE_NS || type == TYPE_PTR)
	{
		std::string name;
		if (readName(message, rdataOffset, name))
		{
			return name;
		}
	}
	return std::format("<{} bytes>", rdataLength);
}

} // namespace

std::optional<DnsMessage> parseDns(Bytes message)
{
	if (message.size() < HEADER_LENGTH)
	{
		return std::nullopt;
	}

	DnsMessage out;
	out.id = readU16(message, 0);
	const std::uint16_t flags = readU16(message, 2);
	out.isResponse = (flags & 0x8000) != 0;
	out.opcode = static_cast<std::uint8_t>(flags >> 11 & 0x0F);
	out.rcode = static_cast<std::uint8_t>(flags & 0x0F);
	out.questionCount = readU16(message, 4);
	out.answerCount = readU16(message, 6);

	std::size_t position = HEADER_LENGTH;

	// answers come after every question, so all questions must be read to find them
	if (out.questionCount > MAX_QUESTIONS)
	{
		out.malformed = true;
		return out;
	}
	for (std::size_t i = 0; i < out.questionCount; ++i)
	{
		DnsQuestion question;
		const auto next = readName(message, position, question.name);
		if (!next || *next + 4 > message.size())
		{
			out.malformed = true;
			return out;
		}
		question.type = readU16(message, *next);
		question.recordClass = readU16(message, *next + 2);
		out.questions.push_back(std::move(question));
		position = *next + 4;
	}

	for (std::size_t i = 0; i < out.answerCount && i < MAX_ANSWERS; ++i)
	{
		DnsAnswer answer;
		const auto next = readName(message, position, answer.name);
		// type (2) + class (2) + ttl (4) + data length (2) follow the name
		if (!next || *next + 10 > message.size())
		{
			out.malformed = true;
			return out;
		}
		answer.type = readU16(message, *next);
		answer.ttl = readU32(message, *next + 4);
		const std::size_t rdataLength = readU16(message, *next + 8);
		const std::size_t rdataOffset = *next + 10;
		if (rdataOffset + rdataLength > message.size())
		{
			out.malformed = true;
			return out;
		}
		answer.data = answerData(message, answer.type, rdataOffset, rdataLength);
		out.answers.push_back(std::move(answer));
		position = rdataOffset + rdataLength;
	}
	return out;
}

std::string dnsTypeName(std::uint16_t type)
{
	switch (type)
	{
	case 1: return "A";
	case 2: return "NS";
	case 5: return "CNAME";
	case 6: return "SOA";
	case 12: return "PTR";
	case 15: return "MX";
	case 16: return "TXT";
	case 28: return "AAAA";
	case 33: return "SRV";
	case 64: return "SVCB";
	case 65: return "HTTPS";
	case 255: return "ANY";
	default: return std::format("TYPE{}", type);
	}
}

std::string dnsRcodeName(std::uint8_t rcode)
{
	switch (rcode)
	{
	case 0: return "NOERROR";
	case 1: return "FORMERR";
	case 2: return "SERVFAIL";
	case 3: return "NXDOMAIN";
	case 4: return "NOTIMP";
	case 5: return "REFUSED";
	default: return std::format("RCODE{}", rcode);
	}
}

} // namespace wiresight
