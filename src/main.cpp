#include "capture.hpp"
#include "demo.hpp"
#include "format.hpp"
#include "packet.hpp"
#include "scan.hpp"
#include "watch.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <format>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace
{

using namespace wiresight;

/** WHAT: version shown by --version. */
constexpr std::string_view VERSION = "1.0.0";

/**
 * WHAT:   Bytes kept per captured frame.
 * WHY:    Enough for every header and most DNS answers, but most of a web
 *         page or file transfer is never copied: less memory, and less
 *         private data passing through the program.
 */
constexpr int SNAP_LENGTH = 512;

/** WHAT: how long a read waits on a quiet network before checking for Ctrl+C. */
constexpr int READ_TIMEOUT_MS = 250;

constexpr std::string_view USAGE = R"(usage: wiresight [options]
  -l, --list             list the interfaces you can capture on
  -i, --interface N      capture live on interface number N from --list (or its name)
  -r, --read FILE        decode a saved .pcap file instead
  -f, --filter EXPR      capture filter, e.g. "tcp port 445" or "udp port 53"
  -c, --count N          stop after N packets
  -v, --verbose          show every layer of each packet
  -p, --promiscuous      also capture traffic for other machines on the network
  -w, --watch            show the scan watch: a pixel-art view of port scans instead of packet lines
      --demo             play a built-in port scan in the scan watch (no capture, no admin rights)
      --scan-threshold N distinct ports from one address within 10 s that count as a scan (default 20)
      --version          show the version and the capture library
  -h, --help             show this help

Port scans are always detected: a "PORT SCAN" line appears among the packets.

Live capture needs Npcap (Windows, https://npcap.com) or libpcap (Linux, macOS).
Only capture on networks you own or have permission to monitor.
)";

/** WHAT: set by the Ctrl+C handler; checked between packets. */
std::atomic<bool> stopRequested{false};

/**
 * WHAT:   Handles Ctrl+C.
 * WHY:    A signal handler may only do async-signal-safe work, so it just
 *         sets a flag and the capture loop stops cleanly, closing the handle.
 *
 * @param signal the signal number (SIGINT)
 */
extern "C" void onInterrupt(int signal)
{
	(void) signal;
	stopRequested = true;
}

/** WHAT: the parsed command line. */
struct Options
{
	/** WHAT: --list was given. */
	bool list = false;
	/** WHAT: --verbose was given. */
	bool verbose = false;
	/** WHAT: --promiscuous was given. */
	bool promiscuous = false;
	/** WHAT: --version was given. */
	bool version = false;
	/** WHAT: --watch was given (or --demo, which implies it). */
	bool watch = false;
	/** WHAT: --demo was given. */
	bool demo = false;
	/** WHAT: the value of --scan-threshold. */
	std::size_t scanThreshold = 20;
	/** WHAT: --help was given, or no arguments at all. */
	bool help = false;
	/** WHAT: the value of --interface, or "". */
	std::string interface;
	/** WHAT: the value of --read, or "". */
	std::string file;
	/** WHAT: the value of --filter, or "". */
	std::string filter;
	/** WHAT: the value of --count, or 0 for no limit. */
	std::size_t count = 0;
};

/**
 * WHAT:   Thrown for bad command-line input.
 * WHY:    Lets main print the message with the usage and exit with code 2,
 *         the usual code for "you called it wrong".
 */
class UsageError : public std::runtime_error
{
public:
	using std::runtime_error::runtime_error;
};

/**
 * WHAT:   Parses a positive whole number.
 * WHY:    std::from_chars rejects "12abc" and negative numbers, which
 *         std::stoi would partly accept.
 * RETURN: the number, or nothing if text is not a whole number above 0
 *
 * @param text the text to parse
 * @return the number, or std::nullopt
 */
std::optional<std::size_t> parsePositive(std::string_view text)
{
	std::size_t value = 0;
	const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
	if (error != std::errc() || end != text.data() + text.size() || value == 0)
	{
		return std::nullopt;
	}
	return value;
}

/**
 * WHAT:   Reads the command line into Options.
 * WHY:    Checks every rule up front (one source, a value after each
 *         option) so capturing never starts with half-valid settings.
 * RETURN: the options
 * THROWS: UsageError with a message naming the problem
 *
 * @param argc argument count from main
 * @param argv arguments from main
 * @return the parsed options
 * @throws UsageError on bad input
 */
Options parseArguments(int argc, char** argv)
{
	Options options;
	options.help = argc == 1;
	for (int i = 1; i < argc; ++i)
	{
		const std::string_view argument = argv[i];
		const auto value = [&]() -> std::string {
			if (i + 1 >= argc)
			{
				throw UsageError(std::string(argument) + " needs a value");
			}
			return argv[++i];
		};

		if (argument == "-l" || argument == "--list") options.list = true;
		else if (argument == "-i" || argument == "--interface") options.interface = value();
		else if (argument == "-r" || argument == "--read") options.file = value();
		else if (argument == "-f" || argument == "--filter") options.filter = value();
		else if (argument == "-v" || argument == "--verbose") options.verbose = true;
		else if (argument == "-p" || argument == "--promiscuous") options.promiscuous = true;
		else if (argument == "--version") options.version = true;
		else if (argument == "-w" || argument == "--watch") options.watch = true;
		else if (argument == "--demo") options.demo = options.watch = true;
		else if (argument == "--scan-threshold")
		{
			const std::string text = value();
			const auto threshold = parsePositive(text);
			if (!threshold || *threshold < 2)
			{
				throw UsageError("--scan-threshold needs a whole number of 2 or more, got '" + text + "'");
			}
			options.scanThreshold = *threshold;
		}
		else if (argument == "-h" || argument == "--help") options.help = true;
		else if (argument == "-c" || argument == "--count")
		{
			const std::string text = value();
			const auto count = parsePositive(text);
			if (!count)
			{
				throw UsageError("-c needs a whole number above 0, got '" + text + "'");
			}
			options.count = *count;
		}
		else
		{
			throw UsageError("unknown option " + std::string(argument));
		}
	}

	const int sources = (options.list ? 1 : 0) + (options.interface.empty() ? 0 : 1) + (options.file.empty() ? 0 : 1)
		+ (options.demo ? 1 : 0);
	if (!options.help && !options.version && sources != 1)
	{
		throw UsageError("choose exactly one of --list, --interface, --read or --demo");
	}
	return options;
}

/**
 * WHAT:   Prints the capture interfaces with numbers.
 * WHY:    On Windows the real names are GUIDs nobody can type.
 * THROWS: CaptureError if the capture library is missing
 *
 * @throws CaptureError if listing fails
 */
void printDevices()
{
	const std::vector<Device> devices = Capture::listDevices();
	if (devices.empty())
	{
		std::cout << "no interfaces found (on Linux, try running with sudo)\n";
		return;
	}
	for (std::size_t i = 0; i < devices.size(); ++i)
	{
		const Device& device = devices[i];
		std::cout << std::format("{:>3}  {}", i + 1, device.description.empty() ? device.name : device.description);
		if (device.loopback)
		{
			std::cout << "  (loopback)";
		}
		for (std::size_t a = 0; a < device.addresses.size(); ++a)
		{
			std::cout << (a == 0 ? "  " : ", ") << device.addresses[a];
		}
		std::cout << '\n';
	}
}

/**
 * WHAT:   Turns "-i 3" into the third interface's name; other text is used as is.
 * WHY:    Numbers are easy to type; names still work for scripts.
 * RETURN: the interface name to open
 * THROWS: UsageError if the number is out of range
 *
 * @param choice the text after -i
 * @return the interface name
 * @throws UsageError if there is no interface with that number
 */
std::string resolveInterface(const std::string& choice)
{
	const auto number = parsePositive(choice);
	if (!number)
	{
		return choice;
	}
	const std::vector<Device> devices = Capture::listDevices();
	if (*number > devices.size())
	{
		throw UsageError(std::format("there is no interface {}; run wiresight --list", *number));
	}
	return devices[*number - 1].name;
}

/**
 * WHAT:   Turns on UTF-8 output and ANSI escape codes in the Windows console.
 * WHY:    The scan watch draws with half-block characters and 24-bit
 *         colour; Windows Terminal and the classic console both support
 *         them, but only once a program asks. Elsewhere this does nothing.
 */
void prepareTerminal()
{
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
	const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode = 0;
	if (out != INVALID_HANDLE_VALUE && GetConsoleMode(out, &mode))
	{
		SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}
#endif
}

/**
 * WHAT:   Feeds packets to the scan detector and shows the result, either
 *         as alert lines among the packet lines or as the scan watch.
 * WHY:    Live capture, files and the demo all produce packets the same
 *         way, so they share one place that detects and draws.
 */
class Watcher
{
public:
	/**
	 * WHAT:   Starts watching.
	 * POST:   in watch mode the screen is cleared and the cursor hidden
	 *
	 * @param options     the parsed options
	 * @param sourceLabel "LIVE", "FILE" or "DEMO", shown in the title
	 */
	Watcher(const Options& options, std::string sourceLabel)
		: options_(options), detector_(options.scanThreshold)
	{
		status_.sourceLabel = std::move(sourceLabel);
		if (options_.watch)
		{
			prepareTerminal();
			std::cout << "\x1b[2J\x1b[?25l" << renderWatch(nullptr, status_, 0) << std::flush;
		}
	}

	Watcher(const Watcher&) = delete;
	Watcher& operator=(const Watcher&) = delete;

	/**
	 * WHAT:   Shows the cursor again.
	 * WHY:    An error or Ctrl+C must not leave the terminal without a cursor.
	 */
	~Watcher()
	{
		if (options_.watch)
		{
			std::cout << "\x1b[?25h" << std::flush;
		}
	}

	/**
	 * WHAT:   Handles one decoded packet.
	 * POST:   the detector has seen it; in line mode the packet (and any
	 *         alert) is printed; in watch mode a frame may be drawn
	 *
	 * @param packet     the decoded packet
	 * @param timeMicros its capture time, microseconds since 1970
	 * @param timestamp  its time as text, for line mode
	 */
	void onPacket(const DecodedPacket& packet, std::int64_t timeMicros, const std::string& timestamp)
	{
		++status_.packets;
		status_.nowMicros = timeMicros;
		const std::optional<ScanAlert> alert = detector_.observe(packet, timeMicros);
		if (alert)
		{
			status_.alert = alert;
		}

		if (options_.watch)
		{
			draw(false);
			return;
		}
		std::cout << timestamp << "  " << summarize(packet) << '\n';
		if (options_.verbose)
		{
			std::cout << describeLayers(packet);
		}
		if (alert)
		{
			std::cout << std::format("!!  PORT SCAN  {} -> {}: {} ports in {:.2f} s\n", alert->source, alert->target,
				alert->ports, static_cast<double>(alert->elapsedMicros) / 1e6);
		}
		std::cout.flush();
	}

	/**
	 * WHAT:   Draws a frame if enough time has passed since the last one.
	 * WHY:    Drawing every packet would flood the terminal during a fast
	 *         scan; about 12 frames a second is smooth and cheap. Also
	 *         called while waiting, so the animation keeps moving.
	 *
	 * @param force draw now, whatever the time
	 */
	void draw(bool force)
	{
		if (!options_.watch)
		{
			return;
		}
		const auto now = std::chrono::steady_clock::now();
		if (!force && now - lastDraw_ < std::chrono::milliseconds(80))
		{
			return;
		}
		lastDraw_ = now;
		std::cout << renderWatch(detector_.busiest(), status_, tick_++) << std::flush;
	}

	/**
	 * WHAT:   Ends the run: the last frame in watch mode, then a summary on stderr.
	 * POST:   the cursor is visible again
	 */
	void finish()
	{
		if (options_.watch)
		{
			status_.finished = true;
			draw(true);
			std::cout << "\x1b[?25h" << std::flush;
		}
		std::cerr << status_.packets << (status_.packets == 1 ? " packet" : " packets")
				  << (status_.alert ? ", port scan detected\n" : ", no port scan detected\n");
	}

	/**
	 * WHAT:   How many packets have been handled.
	 * RETURN: the count
	 *
	 * @return the packet count
	 */
	std::size_t packets() const
	{
		return status_.packets;
	}

private:
	/** WHAT: the command line, for watch and verbose. */
	const Options& options_;
	/** WHAT: finds the scans. */
	ScanDetector detector_;
	/** WHAT: counts, time and the latest alert, for the view. */
	WatchStatus status_;
	/** WHAT: animation step. */
	int tick_ = 0;
	/** WHAT: when the last frame was drawn. */
	std::chrono::steady_clock::time_point lastDraw_{};
};

/**
 * WHAT:   Reads packets until the count, the end of the file, or Ctrl+C.
 * WHY:    Status goes to stderr and packets to stdout, so the output can be
 *         piped to grep or a file without the status lines.
 * THROWS: CaptureError if reading fails
 *
 * @param capture the open capture
 * @param options the parsed options
 * @throws CaptureError on a read error
 */
void runCapture(Capture& capture, const Options& options)
{
	const int dlt = capture.dataLink();
	const LinkType link = linkTypeFromDlt(dlt);
	if (link == LinkType::Unknown)
	{
		std::cerr << "warning: link type " << dlt << " is not decoded; only lengths will be shown\n";
	}

	std::signal(SIGINT, onInterrupt);
	Watcher watcher(options, options.file.empty() ? "LIVE" : "FILE");
	RawPacket raw;
	while (!stopRequested && (options.count == 0 || watcher.packets() < options.count))
	{
		const ReadResult result = capture.next(raw);
		if (result == ReadResult::Timeout)
		{
			watcher.draw(false);
			continue;
		}
		if (result == ReadResult::End)
		{
			break;
		}

		const DecodedPacket packet = decode(raw.data, link, raw.originalLength);
		watcher.onPacket(packet, raw.seconds * 1'000'000 + raw.microseconds, formatTimestamp(raw.seconds, raw.microseconds));
	}
	watcher.finish();
}

/**
 * WHAT:   Plays the built-in port scan in real time through the decoder,
 *         the detector and the scan watch.
 * WHY:    Anyone can see what wiresight detects in about ten seconds,
 *         without Npcap, admin rights, or scanning a real machine.
 *
 * @param options the parsed options
 */
void runDemo(const Options& options)
{
	std::signal(SIGINT, onInterrupt);
	const std::vector<DemoPacket> packets = scanDemo();
	const auto start = std::chrono::steady_clock::now();
	const std::int64_t base = std::chrono::duration_cast<std::chrono::microseconds>(
		std::chrono::system_clock::now().time_since_epoch()).count();

	Watcher watcher(options, "DEMO");
	for (const DemoPacket& demo : packets)
	{
		const auto due = start + std::chrono::microseconds(demo.offsetMicros);
		while (!stopRequested && std::chrono::steady_clock::now() < due)
		{
			watcher.draw(false);
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}
		if (stopRequested)
		{
			break;
		}
		const DecodedPacket packet = decode(Bytes(demo.frame), LinkType::Ethernet, demo.frame.size());
		watcher.onPacket(packet, base + demo.offsetMicros, "");
	}

	// let the alarm blink for a moment before the final frame
	const auto hold = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
	while (!stopRequested && std::chrono::steady_clock::now() < hold)
	{
		watcher.draw(false);
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	watcher.finish();
}

} // namespace

int main(int argc, char** argv)
{
	Options options;
	try
	{
		options = parseArguments(argc, argv);
	}
	catch (const UsageError& error)
	{
		std::cerr << "error: " << error.what() << "\n\n" << USAGE;
		return 2;
	}

	if (options.help)
	{
		std::cout << USAGE;
		return 0;
	}

	try
	{
		if (options.version)
		{
			std::cout << "wiresight " << VERSION << '\n' << Capture::libraryVersion() << '\n';
			return 0;
		}
		if (options.list)
		{
			printDevices();
			return 0;
		}

		if (options.demo)
		{
			runDemo(options);
			return 0;
		}

		Capture capture = options.file.empty()
			? Capture::openLive(resolveInterface(options.interface), SNAP_LENGTH, options.promiscuous, READ_TIMEOUT_MS)
			: Capture::openFile(options.file);
		if (!options.filter.empty())
		{
			capture.setFilter(options.filter);
		}
		if (options.file.empty() && !options.watch)
		{
			std::cerr << "capturing, press Ctrl+C to stop\n";
		}
		runCapture(capture, options);
		return 0;
	}
	catch (const UsageError& error)
	{
		std::cerr << "error: " << error.what() << '\n';
		return 2;
	}
	catch (const CaptureError& error)
	{
		std::cerr << "error: " << error.what() << '\n';
		return 1;
	}
}
