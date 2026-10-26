#pragma once

#include <cstdint>
#include <vector>

namespace wiresight
{

/** WHAT: one made-up Ethernet frame and when it "arrives". */
struct DemoPacket
{
	/** WHAT: time since the start of the demo, microseconds. */
	std::int64_t offsetMicros = 0;
	/** WHAT: the frame bytes, as a network card would capture them. */
	std::vector<std::uint8_t> frame;
};

/** WHAT: the scanning machine in the demo (RFC 5737 documentation address). */
inline constexpr const char* DEMO_SCANNER = "203.0.113.7";
/** WHAT: the scanned machine in the demo (RFC 5737). */
inline constexpr const char* DEMO_TARGET = "198.51.100.20";

/**
 * WHAT:   A recorded-style port scan, built byte by byte.
 * WHY:    Shows the detector and the watch view working without admin
 *         rights, Npcap, or scanning anything real. The frames go through
 *         the same decoder as a live capture. The story: a second of normal
 *         browsing (which must not raise an alert), then 203.0.113.7 scans
 *         ports 1 to 1024 of 198.51.100.20 the way portscout does (a full
 *         TCP connect: SYN, then SYN-ACK or RST). Ports 22, 80, 443 and 445
 *         are open; 135 to 139 are filtered and never answer.
 * RETURN: the frames in time order
 *
 * @return the demo frames
 */
std::vector<DemoPacket> scanDemo();

} // namespace wiresight
