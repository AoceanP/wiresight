#pragma once

#include "bytes.hpp"

#include <optional>
#include <string>

namespace wiresight
{

/** WHAT: TCP flag bits, as stored in byte 13 of the header. */
namespace tcp_flag
{
/** WHAT: sender has finished sending. */
inline constexpr std::uint8_t FIN = 0x01;
/** WHAT: open a connection (first step of the handshake). */
inline constexpr std::uint8_t SYN = 0x02;
/** WHAT: abort; also the answer from a closed port. */
inline constexpr std::uint8_t RST = 0x04;
/** WHAT: pass the data to the application now. */
inline constexpr std::uint8_t PSH = 0x08;
/** WHAT: the acknowledgment number is valid. */
inline constexpr std::uint8_t ACK = 0x10;
/** WHAT: the urgent pointer is valid. */
inline constexpr std::uint8_t URG = 0x20;
/** WHAT: explicit congestion notification echo. */
inline constexpr std::uint8_t ECE = 0x40;
/** WHAT: congestion window reduced. */
inline constexpr std::uint8_t CWR = 0x80;
} // namespace tcp_flag

/**
 * WHAT:   A TCP header.
 * WHY:    TCP carries web, SSH, SMB and most other traffic; its flags show
 *         the handshake (SYN, SYN-ACK, ACK) and how connections end
 *         (FIN, RST), which is exactly what portscout relies on.
 */
struct TcpSegment
{
	/** WHAT: port on the sender. */
	std::uint16_t sourcePort = 0;
	/** WHAT: port on the receiver, usually the service (443, 22...). */
	std::uint16_t destinationPort = 0;
	/** WHAT: position of this segment's first byte in the sender's stream. */
	std::uint32_t sequence = 0;
	/** WHAT: next byte the sender expects from the other side (valid with ACK). */
	std::uint32_t acknowledgment = 0;
	/** WHAT: header size in bytes, 20 to 60 (options such as MSS make it longer). */
	std::size_t headerLength = 0;
	/** WHAT: the tcp_flag bits. */
	std::uint8_t flags = 0;
	/** WHAT: how many more bytes the sender can receive right now. */
	std::uint16_t window = 0;
	/** WHAT: application data after the header. */
	Bytes payload;
};

/**
 * WHAT:   Decodes a TCP header.
 * WHY:    The data offset field is checked against the captured bytes, so
 *         a header claiming 60 bytes in a 20-byte capture is refused.
 * PRE:    data starts at the TCP header
 * RETURN: the header, or nothing if it is incomplete
 *
 * @param data the transport bytes from the IP layer
 * @return the decoded header, or std::nullopt
 */
std::optional<TcpSegment> parseTcp(Bytes data);

/**
 * WHAT:   Names the flags that are set, e.g. "SYN, ACK".
 * WHY:    Reading "SYN, ACK" is far easier than 0x12, and the order puts
 *         the handshake flags first like Wireshark does.
 * RETURN: the flag names separated by ", ", or "none"
 *
 * @param flags the tcp_flag bits
 * @return the readable flag list
 */
std::string tcpFlagsToString(std::uint8_t flags);

} // namespace wiresight
