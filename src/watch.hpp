#pragma once

#include "scan.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace wiresight
{

/** WHAT: what the watch view needs to know besides the scan itself. */
struct WatchStatus
{
	/** WHAT: where packets come from, e.g. "DEMO", "LIVE", "FILE". */
	std::string sourceLabel;
	/** WHAT: packets read so far. */
	std::size_t packets = 0;
	/** WHAT: time of the latest packet, microseconds since 1970. */
	std::int64_t nowMicros = 0;
	/** WHAT: the latest alert, if any was raised. */
	std::optional<ScanAlert> alert;
	/** WHAT: the input has ended (file or demo finished). */
	bool finished = false;
};

/** WHAT: lines in every frame, so the screen can be redrawn in place. */
inline constexpr int WATCH_LINES = 27;

/**
 * WHAT:   Draws one frame of the scan watch: a pixel-art scanner and
 *         server joined by a wire with packets moving along it, a map of
 *         ports 1 to 1024 (one pixel per port, coloured by what the scan
 *         found), the counts, the open ports, and the alert banner.
 * WHY:    A port scan is hard to picture from a list of packet lines; as a
 *         grid filling up it is obvious at a glance: the sweep, the few
 *         green open ports, and the red alarm. Pixels are drawn with the
 *         half-block character and 24-bit colour, two pixels per cell.
 * PRE:    the terminal understands ANSI colour escapes and UTF-8
 * RETURN: the frame, starting with "cursor home", WATCH_LINES lines long
 *
 * @param track  the scan to show (usually ScanDetector::busiest()), or nullptr
 * @param status counts, time and alert
 * @param tick   animation step, increased once per frame
 * @return the frame text
 */
std::string renderWatch(const ScanTrack* track, const WatchStatus& status, int tick);

/**
 * WHAT:   The common name of a well-known port, e.g. 22 is "ssh".
 * RETURN: the name, or "" if it is not in the short list
 *
 * @param port the port number
 * @return the service name
 */
std::string serviceName(std::uint16_t port);

} // namespace wiresight
