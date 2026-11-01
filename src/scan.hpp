#pragma once

#include "packet.hpp"

#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <optional>
#include <unordered_set>
#include <string>
#include <tuple>
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
 * WHAT:   Counts the distinct keys among the events of a sliding time window.
 * WHY:    Both rules are "how many different X within the window": ports for
 *         a port scan, hosts for a sweep. A queue plus per-key counts makes
 *         each event cost the same however big the window gets.
 *
 * @tparam Key the thing counted (a port number or an address)
 */
template <typename Key>
class DistinctWindow
{
public:
	/**
	 * WHAT:   Adds one event and drops events older than the window.
	 * PRE:    times do not go backwards by more than the window
	 * RETURN: how many distinct keys are now inside the window
	 *
	 * @param timeMicros   the event time
	 * @param key          the event's key
	 * @param windowMicros the window length
	 * @return the distinct count
	 */
	std::size_t add(std::int64_t timeMicros, const Key& key, std::int64_t windowMicros)
	{
		events_.emplace_back(timeMicros, key);
		++counts_[key];
		while (!events_.empty() && events_.front().first < timeMicros - windowMicros)
		{
			const auto found = counts_.find(events_.front().second);
			if (--found->second == 0)
			{
				counts_.erase(found);
			}
			events_.pop_front();
		}
		return counts_.size();
	}

	/**
	 * WHAT:   The time of the oldest event still in the window.
	 * PRE:    add() has been called at least once
	 * RETURN: microseconds
	 *
	 * @return the oldest time
	 */
	std::int64_t oldest() const
	{
		return events_.front().first;
	}

private:
	/** WHAT: (time, key) of the events inside the window, oldest first. */
	std::deque<std::pair<std::int64_t, Key>> events_;
	/** WHAT: how many of those events have each key. */
	std::unordered_map<Key, std::size_t> counts_;
};

/**
 * WHAT:   Counts the distinct keys first seen within a long sliding window.
 * WHY:    The slow rules look back 15 minutes. Keeping every event for that
 *         long (as DistinctWindow does) would let a flood of repeated SYNs
 *         grow memory; here a key is stored once, when first seen, and
 *         expires one window later. Memory is bounded by the number of
 *         distinct keys (at most 65,535 ports), whatever the packet rate.
 *
 * @tparam Key the thing counted (a port number or an address)
 */
template <typename Key>
class FirstSeenWindow
{
public:
	/**
	 * WHAT:   Expires keys first seen before the window, then adds this key if it is new.
	 * PRE:    times do not go backwards by more than the window
	 * RETURN: how many distinct keys were first seen inside the window
	 *
	 * @param timeMicros   the event time
	 * @param key          the event's key
	 * @param windowMicros the window length
	 * @return the distinct count
	 */
	std::size_t add(std::int64_t timeMicros, const Key& key, std::int64_t windowMicros)
	{
		while (!order_.empty() && order_.front().first < timeMicros - windowMicros)
		{
			keys_.erase(order_.front().second);
			order_.pop_front();
		}
		if (keys_.insert(key).second)
		{
			order_.emplace_back(timeMicros, key);
		}
		return keys_.size();
	}

	/**
	 * WHAT:   The time the oldest counted key was first seen.
	 * PRE:    add() has been called at least once
	 * RETURN: microseconds
	 *
	 * @return the oldest time
	 */
	std::int64_t oldest() const
	{
		return order_.front().first;
	}

private:
	/** WHAT: (first-seen time, key), oldest first; one entry per key. */
	std::deque<std::pair<std::int64_t, Key>> order_;
	/** WHAT: the keys currently counted. */
	std::unordered_set<Key> keys_;
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
	/** WHAT: the port of the latest SYN, which the watch view flashes. */
	std::uint16_t lastPort = 0;
	/** WHAT: every probed port and what is known about it. */
	std::map<std::uint16_t, PortState> ports;
	/** WHAT: an alert has been raised for this pair. */
	bool alerted = false;
	/** WHAT: a slow-scan alert has been raised for this pair. */
	bool slowAlerted = false;
	/** WHAT: the ports probed inside the detection window. */
	DistinctWindow<std::uint16_t> recent;
	/** WHAT: the ports first probed inside the slow window. */
	FirstSeenWindow<std::uint16_t> slow;

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
 * WHAT:   Everything seen of one source probing one port across one subnet.
 * WHY:    A sweep (one port, many hosts) is the other half of reconnaissance:
 *         "which machines here run SSH?" rather than "what runs on this machine?".
 */
struct SweepTrack
{
	/** WHAT: the address sending SYNs. */
	std::string source;
	/** WHAT: the subnet being swept, e.g. "198.51.100.0/24". */
	std::string subnet;
	/** WHAT: the destination port of every probe. */
	std::uint16_t port = 0;
	/** WHAT: time of the latest SYN. */
	std::int64_t lastMicros = 0;
	/** WHAT: an alert has been raised for this sweep. */
	bool alerted = false;
	/** WHAT: a slow-sweep alert has been raised for this sweep. */
	bool slowAlerted = false;
	/** WHAT: the hosts probed inside the detection window. */
	DistinctWindow<std::string> recent;
	/** WHAT: the hosts first probed inside the slow window. */
	FirstSeenWindow<std::string> slow;
};

/**
 * WHAT:   Which pattern an alert is about.
 */
enum class ScanKind : std::uint8_t
{
	/** WHAT: one source, one target, many ports. */
	PortScan,
	/** WHAT: one source, one port, many hosts of one subnet. */
	HostSweep
};

/**
 * WHAT:   A raised alarm: a port scan or a host sweep.
 * WHY:    Carries the numbers a person needs to judge it: who, whom, how
 *         many ports or hosts, and how quickly.
 */
struct ScanAlert
{
	/** WHAT: port scan or host sweep. */
	ScanKind kind = ScanKind::PortScan;
	/** WHAT: found by the slow window: probes spread out to stay under the fast alarm. */
	bool slow = false;
	/** WHAT: the scanner's address. */
	std::string source;
	/** WHAT: the scanned address, or the swept subnet for a sweep. */
	std::string target;
	/** WHAT: distinct ports probed inside the window (port scan), or 0. */
	std::size_t ports = 0;
	/** WHAT: the probed port (sweep), or 0. */
	std::uint16_t port = 0;
	/** WHAT: distinct hosts probed inside the window (sweep), or 0. */
	std::size_t hosts = 0;
	/** WHAT: time from the oldest of those probes to the one that fired it. */
	std::int64_t elapsedMicros = 0;
};

/**
 * WHAT:   Spots TCP reconnaissance: port scans (one source sending SYNs to
 *         many different ports of one target) and host sweeps (one source
 *         sending SYNs to one port on many hosts of one subnet), each within
 *         a short window.
 * WHY:    Normal clients reuse a few ports (a browser opens many
 *         connections, all to 443); a scanner touches dozens to thousands.
 *         Counting distinct ports, not SYNs, keeps busy browsers quiet.
 *         Sweeps are counted per /24 (IPv4) or /64 (IPv6) subnet, because a
 *         browser reaching many content servers on 443 spreads across the
 *         internet, while a sweep walks one network. Counting is incremental,
 *         so a full 65,535-port scan costs the same per packet as a small one.
 *
 *         Patient scanners pace themselves under that window (portscout
 *         --rate 1 sends 10 probes in 10 s, half the threshold), so a
 *         second, slow window looks back 15 minutes: 100 different ports,
 *         or hosts, in that time is a slow scan. A pair or sweep already
 *         reported by the fast rule is not reported again as slow.
 *
 *         The detector also defends itself: every SYN from a new address
 *         creates a record, so a flood of SYNs from forged addresses could
 *         otherwise grow memory without limit. At most maxTracked pairs and
 *         maxTracked sweeps are kept; when full, the least recently active
 *         one is dropped (never the scan on screen), and drops are counted
 *         so the flood itself is visible.
 */
class ScanDetector
{
public:
	/**
	 * WHAT:   Creates a detector.
	 * PRE:    threshold >= 2, windowMicros > 0, sweepThreshold >= 2, maxTracked >= 2,
	 *         slowThreshold >= 2, slowWindowMicros > windowMicros
	 *
	 * @param threshold        distinct ports in the window that raise a port-scan alert
	 * @param windowMicros     the window length, in microseconds
	 * @param sweepThreshold   distinct hosts of one subnet in the window that raise a sweep alert
	 * @param maxTracked       the most pairs (and, separately, sweeps) remembered at once
	 * @param slowThreshold    distinct ports (or hosts) in the slow window that raise a slow alert
	 * @param slowWindowMicros the slow window length, in microseconds; also how long a quiet
	 *                         pair or sweep is remembered
	 */
	explicit ScanDetector(std::size_t threshold = 20, std::int64_t windowMicros = 10'000'000,
		std::size_t sweepThreshold = 20, std::size_t maxTracked = 4096, std::size_t slowThreshold = 100,
		std::int64_t slowWindowMicros = 15 * 60'000'000LL);

	/**
	 * WHAT:   Looks at one packet; only TCP SYN, SYN-ACK and RST matter.
	 * WHY:    SYN (without ACK) is a probe; the target's SYN-ACK or RST is
	 *         the answer that marks the port open or closed.
	 * PRE:    timeMicros does not go backwards by more than the window
	 * POST:   the pair's and sweep's tracks are updated; idle ones are forgotten,
	 *         and the least recently active are dropped when the tables are full
	 * RETURN: an alert the first time a pair or sweep crosses its threshold, else
	 *         nothing (if both cross on the same packet, the port scan is returned
	 *         and the sweep on its next probe)
	 *
	 * @param packet     the decoded packet
	 * @param timeMicros the capture time, microseconds since 1970
	 * @return the new alert, or std::nullopt
	 */
	std::optional<ScanAlert> observe(const DecodedPacket& packet, std::int64_t timeMicros);

	/**
	 * WHAT:   The pair with the most probed ports.
	 * WHY:    The watch view shows one scan at a time: the biggest one.
	 *         Kept up to date on every probe, so this is O(1).
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

	/**
	 * WHAT:   How many pairs and sweeps were dropped because a table was full.
	 * WHY:    Normal traffic never fills 4,096 entries within a minute; a
	 *         non-zero count means a flood, most likely of forged addresses.
	 * RETURN: the total dropped since the detector was created
	 *
	 * @return the count
	 */
	std::size_t dropped() const;

private:
	/** WHAT: a pair's key: (source, target). */
	using PairKey = std::pair<std::string, std::string>;
	/** WHAT: a sweep's key: (source, subnet, port). */
	using SweepKey = std::tuple<std::string, std::string, std::uint16_t>;

	/**
	 * WHAT:   A table of tracks that remembers which was touched least recently.
	 * WHY:    Both tables need the same thing: find by key, move to "most
	 *         recent" on every probe, and drop the least recent when full,
	 *         all without scanning the whole table.
	 */
	template <typename Key, typename Track>
	struct Table
	{
		/** WHAT: key to track, plus the track's place in `order`. */
		std::map<Key, std::pair<Track, typename std::list<Key>::iterator>> entries;
		/** WHAT: keys, least recently touched first. */
		std::list<Key> order;
	};

	/** WHAT: (source, target) pairs. */
	Table<PairKey, ScanTrack> pairs_;
	/** WHAT: (source, subnet, port) sweeps. */
	Table<SweepKey, SweepTrack> sweeps_;
	/** WHAT: the pair with the most probed ports, or nullptr. */
	const ScanTrack* busiest_ = nullptr;
	/** WHAT: distinct ports that raise an alert. */
	std::size_t threshold_;
	/** WHAT: how far back the distinct counts look. */
	std::int64_t windowMicros_;
	/** WHAT: distinct hosts that raise a sweep alert. */
	std::size_t sweepThreshold_;
	/** WHAT: the most pairs, and the most sweeps, kept at once. */
	std::size_t maxTracked_;
	/** WHAT: distinct ports or hosts in the slow window that raise a slow alert. */
	std::size_t slowThreshold_;
	/** WHAT: how far back the slow counts look, and how long quiet entries are kept. */
	std::int64_t slowWindowMicros_;
	/** WHAT: entries dropped because a table was full. */
	std::size_t dropped_ = 0;
	/** WHAT: packets seen since the last clean-up of idle entries. */
	std::size_t sinceCleanup_ = 0;

	/**
	 * WHAT:   Finds or creates a track and marks it most recently touched.
	 * WHY:    One place for the cap: when the table is full, the least
	 *         recently touched entry is dropped first, skipping `keep`.
	 * RETURN: the track, and whether it was just created
	 *
	 * @param table the table
	 * @param key   the track's key
	 * @param keep  a track that must never be dropped (the one on screen), or nullptr
	 * @return (track, created)
	 */
	template <typename Key, typename Track>
	std::pair<Track&, bool> touch(Table<Key, Track>& table, const Key& key, const void* keep);

	/**
	 * WHAT:   Records a probe in the pair's track, creating it if needed.
	 * RETURN: a port-scan alert the first time the pair crosses the threshold
	 *
	 * @param from       the scanner
	 * @param to         the target
	 * @param port       the probed port
	 * @param timeMicros the probe time
	 * @return the alert, or std::nullopt
	 */
	std::optional<ScanAlert> probePair(const std::string& from, const std::string& to, std::uint16_t port,
		std::int64_t timeMicros);

	/**
	 * WHAT:   Records a probe in the sweep it belongs to, creating it if needed.
	 * RETURN: a sweep alert the first time the sweep crosses the threshold
	 *
	 * @param from       the scanner
	 * @param to         the target host
	 * @param subnet     the target's subnet
	 * @param port       the probed port
	 * @param timeMicros the probe time
	 * @return the alert, or std::nullopt
	 */
	std::optional<ScanAlert> probeSweep(const std::string& from, const std::string& to, const std::string& subnet,
		std::uint16_t port, std::int64_t timeMicros);

	/**
	 * WHAT:   Forgets pairs and sweeps that have been quiet for a whole slow window.
	 * WHY:    Keeps memory small on a long capture: every connection
	 *         ever made would otherwise stay in the map. Quiet for less than
	 *         the slow window could still be a slow scan pausing between probes.
	 *
	 * @param nowMicros the current capture time
	 */
	void forgetIdle(std::int64_t nowMicros);
};

} // namespace wiresight
