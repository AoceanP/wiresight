#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

struct pcap;

namespace wiresight
{

/**
 * WHAT:   An error from the capture library: Npcap missing, bad
 *         interface, bad filter, unreadable file.
 * WHY:    One exception type lets main print a clear message and exit 1.
 */
class CaptureError : public std::runtime_error
{
public:
	using std::runtime_error::runtime_error;
};

/** WHAT: one network interface that can be captured on. */
struct Device
{
	/** WHAT: the system name, e.g. \Device\NPF_{GUID} on Windows or eth0 on Linux. */
	std::string name;
	/** WHAT: a readable name, e.g. "Intel(R) Ethernet Connection", or "" if none. */
	std::string description;
	/** WHAT: the interface's IPv4 and IPv6 addresses as text. */
	std::vector<std::string> addresses;
	/** WHAT: true for the loopback adapter (127.0.0.1 / ::1 traffic). */
	bool loopback = false;
};

/** WHAT: one captured frame, copied out of the capture library's buffer. */
struct RawPacket
{
	/** WHAT: capture time, seconds since 1970. */
	std::int64_t seconds = 0;
	/** WHAT: capture time, the part of a second. */
	std::int64_t microseconds = 0;
	/** WHAT: the frame's size on the wire. */
	std::size_t originalLength = 0;
	/** WHAT: the captured bytes (at most the snapshot length). */
	std::vector<std::uint8_t> data;
};

/** WHAT: what Capture::next found. */
enum class ReadResult
{
	/** WHAT: a packet was read. */
	Packet,
	/** WHAT: no packet arrived before the read timeout; try again. */
	Timeout,
	/** WHAT: the end of a capture file. */
	End
};

/**
 * WHAT:   An open capture: a live interface or a .pcap file.
 * WHY:    Wraps the C library handle (RAII), so it is always closed, even
 *         when an exception is thrown. It can be moved but not copied, so
 *         two objects never close the same handle.
 */
class Capture
{
public:
	/**
	 * WHAT:   Lists the interfaces that can be captured on.
	 * WHY:    Windows interface names are GUIDs, so users pick by number.
	 * RETURN: the interfaces, in the library's order
	 * THROWS: CaptureError if Npcap/libpcap is missing or fails
	 *
	 * @return the interfaces
	 * @throws CaptureError if listing fails
	 */
	static std::vector<Device> listDevices();

	/**
	 * WHAT:   Starts capturing on a live interface.
	 * WHY:    snapLength limits how much of each frame is kept, so payloads
	 *         are mostly never copied; promiscuous mode also captures traffic
	 *         addressed to other machines.
	 * PRE:    device is a name from listDevices()
	 * THROWS: CaptureError if the interface cannot be opened
	 *
	 * @param device      the interface name
	 * @param snapLength  the most bytes kept per frame
	 * @param promiscuous whether to capture other machines' traffic too
	 * @param timeoutMs   how long next() waits before returning Timeout
	 * @return the open capture
	 * @throws CaptureError if opening fails
	 */
	static Capture openLive(const std::string& device, int snapLength, bool promiscuous, int timeoutMs);

	/**
	 * WHAT:   Opens a saved capture file (.pcap, or .pcapng with recent libpcap).
	 * WHY:    Files from Wireshark can be replayed and decoded the same way
	 *         as live traffic, without needing any permissions.
	 * THROWS: CaptureError if the file cannot be read
	 *
	 * @param path the file to read
	 * @return the open capture
	 * @throws CaptureError if opening fails
	 */
	static Capture openFile(const std::string& path);

	/**
	 * WHAT:   Takes over another capture's handle.
	 * WHY:    Lets the factory functions return a Capture by value.
	 * POST:   other no longer owns a handle
	 *
	 * @param other the capture to move from
	 */
	Capture(Capture&& other) noexcept;

	/**
	 * WHAT:   Closes this handle and takes over another's.
	 * WHY:    Completes the move-only design.
	 * POST:   other no longer owns a handle
	 *
	 * @param other the capture to move from
	 * @return this capture
	 */
	Capture& operator=(Capture&& other) noexcept;

	Capture(const Capture&) = delete;
	Capture& operator=(const Capture&) = delete;

	/** WHAT: closes the capture handle, if any. */
	~Capture();

	/**
	 * WHAT:   Applies a BPF filter, e.g. "tcp port 445" or "udp port 53".
	 * WHY:    The kernel driver drops unwanted packets before they are
	 *         copied, which is far cheaper than filtering in this program.
	 * THROWS: CaptureError if the expression is not valid BPF
	 *
	 * @param expression the filter in tcpdump/Wireshark capture-filter syntax
	 * @throws CaptureError if the filter is invalid
	 */
	void setFilter(const std::string& expression);

	/**
	 * WHAT:   Reports the capture's first header type.
	 * WHY:    Needed to pick Ethernet, loopback or raw IP decoding.
	 * RETURN: the libpcap DLT number
	 *
	 * @return the data link type
	 */
	int dataLink() const;

	/**
	 * WHAT:   Reads the next packet.
	 * WHY:    Returns Timeout regularly on a quiet network, so the caller
	 *         can notice Ctrl+C instead of blocking forever.
	 * POST:   on Packet, packet holds a copy of the frame
	 * THROWS: CaptureError if the read fails
	 *
	 * @param packet receives the frame
	 * @return Packet, Timeout or End
	 * @throws CaptureError on a read error
	 */
	ReadResult next(RawPacket& packet);

	/**
	 * WHAT:   Reports the capture library's version, e.g. "Npcap version 1.80".
	 * WHY:    Shown by --version, which helps when reporting problems.
	 * THROWS: CaptureError if the library is missing
	 *
	 * @return the version text
	 * @throws CaptureError if Npcap/libpcap is not installed
	 */
	static std::string libraryVersion();

private:
	/**
	 * WHAT:   Wraps an already opened handle.
	 * WHY:    Private, so a Capture can only come from the factory functions.
	 *
	 * @param handle the open pcap handle
	 */
	explicit Capture(::pcap* handle);

	/** WHAT: the C library handle, or nullptr after a move. */
	::pcap* handle_;
};

} // namespace wiresight
