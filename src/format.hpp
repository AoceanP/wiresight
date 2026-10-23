#pragma once

#include "packet.hpp"

#include <cstdint>
#include <string>

namespace wiresight
{

/**
 * WHAT:   Formats a capture time as local "HH:MM:SS.microseconds".
 * WHY:    Microseconds show how quickly packets follow each other, e.g. the
 *         gap between a SYN and its SYN-ACK is the network round trip.
 * PRE:    0 <= microseconds < 1,000,000
 * RETURN: the time of day, e.g. "14:02:11.123456"
 *
 * @param seconds      seconds since 1970 (from the pcap header)
 * @param microseconds the part of a second
 * @return the formatted time
 */
std::string formatTimestamp(std::int64_t seconds, std::int64_t microseconds);

/**
 * WHAT:   Describes a packet in one line, using its highest decoded layer.
 * WHY:    One line per packet keeps a busy capture readable, like
 *         Wireshark's packet list; notes are appended after a "!".
 * RETURN: e.g. "TCP   192.168.1.5:51256 -> 93.184.216.34:443  [SYN] seq=100 len=0"
 *
 * @param packet the decoded packet
 * @return the summary line, without a timestamp or newline
 */
std::string summarize(const DecodedPacket& packet);

/**
 * WHAT:   Describes every decoded layer, one indented line per layer.
 * WHY:    Verbose mode (-v) is for learning and troubleshooting: it shows
 *         TTLs, header lengths, window sizes and checksums.
 * RETURN: the layer lines, each indented by 4 spaces and ending in a newline
 *
 * @param packet the decoded packet
 * @return the layer description
 */
std::string describeLayers(const DecodedPacket& packet);

} // namespace wiresight
