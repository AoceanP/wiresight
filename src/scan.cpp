#include "scan.hpp"

#include <algorithm>

namespace wiresight
{

namespace
{

/** WHAT: idle entries are looked for once every this many packets. */
constexpr std::size_t CLEANUP_EVERY = 1024;

/**
 * WHAT:   One probe's addresses as text, plus the subnet of its destination.
 */
struct Ends
{
	/** WHAT: the source address. */
	std::string from;
	/** WHAT: the destination address. */
	std::string to;
	/** WHAT: the destination's /24 (IPv4) or /64 (IPv6), e.g. "198.51.100.0/24". */
	std::string subnet;
};

/**
 * WHAT:   The two addresses of a packet as text, IPv4 or IPv6, and the
 *         destination's subnet.
 * WHY:    /24 and /64 are the usual size of one network: a LAN, an office,
 *         a cloud subnet. A sweep walks one of them.
 * RETURN: the addresses, or nothing if the packet has no IP layer
 *
 * @param packet the decoded packet
 * @return the addresses, or std::nullopt
 */
std::optional<Ends> addresses(const DecodedPacket& packet)
{
	if (packet.ipv4)
	{
		Ipv4Address network = packet.ipv4->destination;
		network[3] = 0;
		return Ends{toString(packet.ipv4->source), toString(packet.ipv4->destination), toString(network) + "/24"};
	}
	if (packet.ipv6)
	{
		Ipv6Address network = packet.ipv6->destination;
		std::fill(network.begin() + 8, network.end(), std::uint8_t{0});
		return Ends{toString(packet.ipv6->source), toString(packet.ipv6->destination), toString(network) + "/64"};
	}
	return std::nullopt;
}

} // namespace

std::size_t ScanTrack::count(PortState state) const
{
	return static_cast<std::size_t>(std::count_if(ports.begin(), ports.end(),
		[state](const auto& entry) { return entry.second == state; }));
}

ScanDetector::ScanDetector(std::size_t threshold, std::int64_t windowMicros, std::size_t sweepThreshold,
	std::size_t maxTracked, std::size_t slowThreshold, std::int64_t slowWindowMicros)
	: threshold_(threshold), windowMicros_(windowMicros), sweepThreshold_(sweepThreshold), maxTracked_(maxTracked),
	  slowThreshold_(slowThreshold), slowWindowMicros_(slowWindowMicros)
{
}

template <typename Key, typename Track>
std::pair<Track&, bool> ScanDetector::touch(Table<Key, Track>& table, const Key& key, const void* keep)
{
	// 1. known: move it to the "most recent" end of the order
	const auto found = table.entries.find(key);
	if (found != table.entries.end())
	{
		table.order.splice(table.order.end(), table.order, found->second.second);
		return {found->second.first, false};
	}

	// 2. new and the table is full: drop the least recently touched entry, but never `keep`
	if (table.entries.size() >= maxTracked_)
	{
		auto victim = table.order.begin();
		if (&table.entries.find(*victim)->second.first == keep)
		{
			++victim; // maxTracked_ >= 2, so there is a next one
		}
		table.entries.erase(*victim);
		table.order.erase(victim);
		++dropped_;
	}

	// 3. create it at the "most recent" end
	table.order.push_back(key);
	auto [entry, created] = table.entries.try_emplace(key, Track{}, std::prev(table.order.end()));
	return {entry->second.first, created};
}

std::optional<ScanAlert> ScanDetector::observe(const DecodedPacket& packet, std::int64_t timeMicros)
{
	if (++sinceCleanup_ >= CLEANUP_EVERY)
	{
		forgetIdle(timeMicros);
	}
	if (!packet.tcp)
	{
		return std::nullopt;
	}
	const auto ends = addresses(packet);
	if (!ends)
	{
		return std::nullopt;
	}
	const std::uint8_t flags = packet.tcp->flags;
	const bool syn = (flags & tcp_flag::SYN) != 0;
	const bool ack = (flags & tcp_flag::ACK) != 0;
	const bool rst = (flags & tcp_flag::RST) != 0;

	// an answer from the target: find the scan it belongs to (key is scanner, target).
	// Answers never create or refresh entries, so a flood of forged answers changes nothing.
	if ((syn && ack) || rst)
	{
		const auto found = pairs_.entries.find({ends->to, ends->from});
		if (found == pairs_.entries.end())
		{
			return std::nullopt;
		}
		ScanTrack& track = found->second.first;
		const auto port = track.ports.find(packet.tcp->sourcePort);
		if (port != track.ports.end() && port->second == PortState::Probed)
		{
			port->second = rst ? PortState::Closed : PortState::Open;
			track.lastReply = port->second;
			track.lastReplyMicros = timeMicros;
		}
		return std::nullopt;
	}
	if (!syn)
	{
		return std::nullopt;
	}

	// a probe: SYN without ACK. It counts towards both patterns.
	const std::uint16_t port = packet.tcp->destinationPort;
	std::optional<ScanAlert> scan = probePair(ends->from, ends->to, port, timeMicros);
	std::optional<ScanAlert> sweep = probeSweep(ends->from, ends->to, ends->subnet, port, timeMicros);
	return scan ? scan : sweep;
}

std::optional<ScanAlert> ScanDetector::probePair(const std::string& from, const std::string& to, std::uint16_t port,
	std::int64_t timeMicros)
{
	auto [track, created] = touch(pairs_, PairKey{from, to}, busiest_);
	if (created)
	{
		track.source = from;
		track.target = to;
		track.firstMicros = timeMicros;
	}
	++track.probes;
	track.lastProbeMicros = timeMicros;
	track.lastPort = port;
	auto [entry, isNew] = track.ports.try_emplace(port, PortState::Probed);
	if (!isNew && entry->second == PortState::Unprobed)
	{
		entry->second = PortState::Probed;
	}

	// the busiest pair: most ports, the latest probe winning a tie
	if (busiest_ == nullptr || track.ports.size() >= busiest_->ports.size())
	{
		busiest_ = &track;
	}

	const std::size_t distinct = track.recent.add(timeMicros, port, windowMicros_);
	const std::size_t slow = track.slow.add(timeMicros, port, slowWindowMicros_);
	if (!track.alerted && distinct >= threshold_)
	{
		track.alerted = true;
		return ScanAlert{.kind = ScanKind::PortScan, .source = track.source, .target = track.target,
			.ports = distinct, .elapsedMicros = timeMicros - track.recent.oldest()};
	}
	// the slow rule: only for a pair the fast rule has not already reported
	if (!track.alerted && !track.slowAlerted && slow >= slowThreshold_)
	{
		track.slowAlerted = true;
		return ScanAlert{.kind = ScanKind::PortScan, .slow = true, .source = track.source, .target = track.target,
			.ports = slow, .elapsedMicros = timeMicros - track.slow.oldest()};
	}
	return std::nullopt;
}

std::optional<ScanAlert> ScanDetector::probeSweep(const std::string& from, const std::string& to,
	const std::string& subnet, std::uint16_t port, std::int64_t timeMicros)
{
	auto [sweep, created] = touch(sweeps_, SweepKey{from, subnet, port}, nullptr);
	if (created)
	{
		sweep.source = from;
		sweep.subnet = subnet;
		sweep.port = port;
	}
	sweep.lastMicros = timeMicros;

	const std::size_t hosts = sweep.recent.add(timeMicros, to, windowMicros_);
	const std::size_t slow = sweep.slow.add(timeMicros, to, slowWindowMicros_);
	if (!sweep.alerted && hosts >= sweepThreshold_)
	{
		sweep.alerted = true;
		return ScanAlert{.kind = ScanKind::HostSweep, .source = sweep.source, .target = sweep.subnet, .port = port,
			.hosts = hosts, .elapsedMicros = timeMicros - sweep.recent.oldest()};
	}
	if (!sweep.alerted && !sweep.slowAlerted && slow >= slowThreshold_)
	{
		sweep.slowAlerted = true;
		return ScanAlert{.kind = ScanKind::HostSweep, .slow = true, .source = sweep.source, .target = sweep.subnet,
			.port = port, .hosts = slow, .elapsedMicros = timeMicros - sweep.slow.oldest()};
	}
	return std::nullopt;
}

const ScanTrack* ScanDetector::busiest() const
{
	return busiest_;
}

std::size_t ScanDetector::tracked() const
{
	return pairs_.entries.size();
}

std::size_t ScanDetector::dropped() const
{
	return dropped_;
}

void ScanDetector::forgetIdle(std::int64_t nowMicros)
{
	sinceCleanup_ = 0;
	const auto forget = [](auto& table, auto isIdle) {
		for (auto it = table.entries.begin(); it != table.entries.end();)
		{
			if (isIdle(it->second.first))
			{
				table.order.erase(it->second.second);
				it = table.entries.erase(it);
			}
			else
			{
				++it;
			}
		}
	};
	forget(pairs_, [&](const ScanTrack& track) {
		return &track != busiest_
			&& std::max(track.lastProbeMicros, track.lastReplyMicros) < nowMicros - slowWindowMicros_;
	});
	forget(sweeps_, [&](const SweepTrack& sweep) { return sweep.lastMicros < nowMicros - slowWindowMicros_; });
}

} // namespace wiresight
