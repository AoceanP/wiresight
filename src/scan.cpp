#include "scan.hpp"

#include <algorithm>

namespace wiresight
{

namespace
{

/** WHAT: a pair quiet for this long is forgotten (unless it is still the busiest). */
constexpr std::int64_t IDLE_MICROS = 60'000'000;

/** WHAT: idle pairs are looked for once every this many packets. */
constexpr std::size_t CLEANUP_EVERY = 1024;

/**
 * WHAT:   The two addresses of a packet as text, IPv4 or IPv6.
 * RETURN: (source, destination), or nothing if the packet has no IP layer
 *
 * @param packet the decoded packet
 * @return the addresses, or std::nullopt
 */
std::optional<std::pair<std::string, std::string>> addresses(const DecodedPacket& packet)
{
	if (packet.ipv4)
	{
		return std::pair{toString(packet.ipv4->source), toString(packet.ipv4->destination)};
	}
	if (packet.ipv6)
	{
		return std::pair{toString(packet.ipv6->source), toString(packet.ipv6->destination)};
	}
	return std::nullopt;
}

} // namespace

std::size_t ScanTrack::count(PortState state) const
{
	return static_cast<std::size_t>(std::count_if(ports.begin(), ports.end(),
		[state](const auto& entry) { return entry.second == state; }));
}

ScanDetector::ScanDetector(std::size_t threshold, std::int64_t windowMicros)
	: threshold_(threshold), windowMicros_(windowMicros)
{
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
	const auto& [from, to] = *ends;
	const std::uint8_t flags = packet.tcp->flags;
	const bool syn = (flags & tcp_flag::SYN) != 0;
	const bool ack = (flags & tcp_flag::ACK) != 0;
	const bool rst = (flags & tcp_flag::RST) != 0;

	// an answer from the target: find the scan it belongs to (key is scanner, target)
	if ((syn && ack) || rst)
	{
		const auto found = tracks_.find({to, from});
		if (found == tracks_.end())
		{
			return std::nullopt;
		}
		ScanTrack& track = found->second;
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

	// a probe: SYN without ACK
	ScanTrack& track = tracks_[{from, to}];
	if (track.probes == 0)
	{
		track.source = from;
		track.target = to;
		track.firstMicros = timeMicros;
	}
	++track.probes;
	track.lastProbeMicros = timeMicros;
	const std::uint16_t port = packet.tcp->destinationPort;
	auto [entry, isNew] = track.ports.try_emplace(port, PortState::Probed);
	if (!isNew && entry->second == PortState::Unprobed)
	{
		entry->second = PortState::Probed;
	}

	track.recent.emplace_back(timeMicros, port);
	++track.recentCounts[port];
	while (!track.recent.empty() && track.recent.front().first < timeMicros - windowMicros_)
	{
		const std::uint16_t old = track.recent.front().second;
		track.recent.pop_front();
		if (--track.recentCounts[old] == 0)
		{
			track.recentCounts.erase(old);
		}
	}

	if (track.alerted || track.recentCounts.size() < threshold_)
	{
		return std::nullopt;
	}
	track.alerted = true;
	return ScanAlert{track.source, track.target, track.recentCounts.size(), timeMicros - track.recent.front().first};
}

const ScanTrack* ScanDetector::busiest() const
{
	const ScanTrack* best = nullptr;
	for (const auto& [key, track] : tracks_)
	{
		if (best == nullptr || track.ports.size() > best->ports.size()
			|| (track.ports.size() == best->ports.size() && track.lastProbeMicros > best->lastProbeMicros))
		{
			best = &track;
		}
	}
	return best;
}

std::size_t ScanDetector::tracked() const
{
	return tracks_.size();
}

void ScanDetector::forgetIdle(std::int64_t nowMicros)
{
	sinceCleanup_ = 0;
	const ScanTrack* keep = busiest();
	std::erase_if(tracks_, [&](const auto& entry) {
		const ScanTrack& track = entry.second;
		const std::int64_t last = std::max(track.lastProbeMicros, track.lastReplyMicros);
		return &track != keep && last < nowMicros - IDLE_MICROS;
	});
}

} // namespace wiresight
