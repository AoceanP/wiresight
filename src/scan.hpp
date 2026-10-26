#pragma once

#include "packet.hpp"

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace wiresight
{

/**
 * WHAT:   What wiresight has seen of one port on a scanned machine.
 * WHY:    A port scanner learns the same three answers portscout reports:
 *         SYN-ACK means open, RST means closed, silence means filtered.
 */
enum class PortState : std::uint8_t
{
	/** WHAT: no SYN to this port yet. */
	Unprobed,
	/** WHAT: a SYN was sent but no answer seen (yet, or ever: filtered). */
	Probed,
	/** WHAT: the target answered RST: nothing listens there. */
	Closed,
	/** WHAT: the target answered SYN-ACK: a service listens there. */
	Open
};

/**
 * WHAT:   Everything seen between one scanner and one target.
 * WHY:    A scan is a conversation between two addresses, so tracking the
 *         pair lets the alert and the watch view say who scanned whom.
 */
struct ScanTrack
{
	/** WHAT: the address sending SYNs. */
	std::string source;
	/** WHAT: the address receiving them. */
	std::string target;
	/** WHAT: time of the first SYN, microseconds. */
	std::int64_t firstMicros = 0;
	/** WHAT: time of the latest SYN. */
	std::int64_t lastProbeMicros = 0;
	/** WHAT: time of the latest SYN-ACK or RST from the target, or 0. */
	std::int64_t lastReplyMicros = 0;
	/** WHAT: what the latest answer said (Open or Closed); Probed before any answer. */
	PortState lastReply = PortState::Probed;
	/** WHAT: SYNs seen, counting repeats. */
	std::size_t probes = 0;
	/** WHAT: every probed port and what is known about it. */
	std::map<std::uint16_t, PortState> ports;
	/** WHAT: an alert has been raised for this pair. */
	bool alerted = false;
	/** WHAT: (time, port) of the SYNs inside the detection window, oldest first. */
	std::deque<std::pair<std::int64_t, std::uint16_t>> recent;
	/** WHAT: how many of the recent SYNs went to each port, for counting distinct ports. */
	std::unordered_map<std::uint16_t, std::size_t> recentCounts;

	/**
	 * WHAT:   Counts the ports in one state.
	 * RETURN: how many probed ports are in that state
	 *
	 * @param state the state to count
	 * @return the count
	 */
	std::size_t count(PortState state) const;
};

/**
 * WHAT:   A raised alarm: one address probed many ports on another, fast.
 * WHY:    Carries the numbers a person needs to judge it: who, whom, how
 *         many ports, and how quickly.
 */
struct ScanAlert
{
	/** WHAT: the scanner's address. */
	std::string source;
	/** WHAT: the scanned address. */
	std::string target;
	/** WHAT: distinct ports probed inside the window when the alarm fired. */
	std::size_t ports = 0;
	/** WHAT: time from the oldest of those probes to the one that fired it. */
	std::int64_t elapsedMicros = 0;
};

/**
 * WHAT:   Spots TCP port scans: one source sending SYNs to many different
 *         ports of one target within a short window.
 * WHY:    Normal clients reuse a few ports (a browser opens many
 *         connections, all to 443); a scanner touches dozens to thousands.
 *         Counting distinct ports, not SYNs, keeps busy browsers quiet.
 *         Counting is incremental (a queue plus per-port counts), so a full
 *         65,535-port scan costs the same per packet as a small one.
 */
class ScanDetector
{
public:
	/**
	 * WHAT:   Creates a detector.
	 * PRE:    threshold >= 2 and windowMicros > 0
	 *
	 * @param threshold    distinct ports in the window that raise an alert
	 * @param windowMicros the window length, in microseconds
	 */
	explicit ScanDetector(std::size_t threshold = 20, std::int64_t windowMicros = 10'000'000);

	/**
	 * WHAT:   Looks at one packet; only TCP SYN, SYN-ACK and RST matter.
	 * WHY:    SYN (without ACK) is a probe; the target's SYN-ACK or RST is
	 *         the answer that marks the port open or closed.
	 * PRE:    timeMicros does not go backwards by more than the window
	 * POST:   the pair's track is updated; idle pairs are forgotten
	 * RETURN: an alert the first time a pair crosses the threshold, else nothing
	 *
	 * @param packet     the decoded packet
	 * @param timeMicros the capture time, microseconds since 1970
	 * @return the new alert, or std::nullopt
	 */
	std::optional<ScanAlert> observe(const DecodedPacket& packet, std::int64_t timeMicros);

	/**
	 * WHAT:   The pair with the most probed ports.
	 * WHY:    The watch view shows one scan at a time: the biggest one.
	 * RETURN: the track, or nullptr if no SYN has been seen
	 *
	 * @return the busiest track, or nullptr
	 */
	const ScanTrack* busiest() const;

	/**
	 * WHAT:   How many source/target pairs are being followed.
	 * RETURN: the number of tracks
	 *
	 * @return the count
	 */
	std::size_t tracked() const;

private:
	/** WHAT: (source, target) to its track. */
	std::map<std::pair<std::string, std::string>, ScanTrack> tracks_;
	/** WHAT: distinct ports that raise an alert. */
	std::size_t threshold_;
	/** WHAT: how far back the distinct-port count looks. */
	std::int64_t windowMicros_;
	/** WHAT: packets seen since the last clean-up of idle pairs. */
	std::size_t sinceCleanup_ = 0;

	/**
	 * WHAT:   Forgets pairs that have been quiet for a minute.
	 * WHY:    Keeps memory bounded on a long capture: every connection
	 *         ever made would otherwise stay in the map.
	 *
	 * @param nowMicros the current capture time
	 */
	void forgetIdle(std::int64_t nowMicros);
};

} // namespace wiresight
