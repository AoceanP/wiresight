#include "capture.hpp"

#include "bytes.hpp"

// winsock2.h must come before windows.h and pcap.h, or their declarations clash
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <pcap.h>

#include <cstring>
#include <utility>

namespace wiresight
{

namespace
{

/**
 * WHAT:   The libpcap functions this program uses, as function pointers.
 * WHY:    On Windows, Npcap installs wpcap.dll in System32\Npcap, which is
 *         not on the DLL search path. Loading it at run time by its full
 *         path works without admin rights or PATH changes, and avoids DLL
 *         hijacking (a fake wpcap.dll next to the program being loaded).
 */
struct PcapApi
{
	decltype(&::pcap_findalldevs) findalldevs = nullptr;
	decltype(&::pcap_freealldevs) freealldevs = nullptr;
	decltype(&::pcap_open_live) openLive = nullptr;
	decltype(&::pcap_open_offline) openOffline = nullptr;
	decltype(&::pcap_next_ex) nextEx = nullptr;
	decltype(&::pcap_datalink) datalink = nullptr;
	decltype(&::pcap_compile) compile = nullptr;
	decltype(&::pcap_setfilter) setfilter = nullptr;
	decltype(&::pcap_freecode) freecode = nullptr;
	decltype(&::pcap_geterr) geterr = nullptr;
	decltype(&::pcap_close) close = nullptr;
	decltype(&::pcap_lib_version) libVersion = nullptr;
};

#ifdef _WIN32
/**
 * WHAT:   Looks up one function in wpcap.dll.
 * WHY:    A missing function means a broken or very old install; failing
 *         early with its name is clearer than crashing later.
 * POST:   target points at the function
 * THROWS: CaptureError if the function is missing
 *
 * @tparam Function the function pointer type
 * @param library   the loaded wpcap.dll
 * @param target    receives the function pointer
 * @param name      the exported function name
 * @throws CaptureError if wpcap.dll does not export name
 */
template <typename Function>
void loadFunction(HMODULE library, Function& target, const char* name)
{
	FARPROC address = GetProcAddress(library, name);
	if (address == nullptr)
	{
		throw CaptureError(std::string("wpcap.dll does not export ") + name + "; reinstall Npcap");
	}
	target = reinterpret_cast<Function>(reinterpret_cast<void*>(address));
}
#endif

/**
 * WHAT:   Loads the capture library once and returns its functions.
 * WHY:    Loading lazily means --help and the tests work on a machine
 *         without Npcap; only capturing needs it.
 * RETURN: the loaded functions
 * THROWS: CaptureError if Npcap/libpcap is not installed
 *
 * @return the function table
 * @throws CaptureError if the library cannot be loaded
 */
const PcapApi& pcapApi()
{
	static const PcapApi api = [] {
		PcapApi loaded;
#ifdef _WIN32
		wchar_t systemDirectory[MAX_PATH];
		const UINT length = GetSystemDirectoryW(systemDirectory, MAX_PATH);
		if (length == 0 || length >= MAX_PATH)
		{
			throw CaptureError("could not find the Windows system folder");
		}
		const std::wstring path = std::wstring(systemDirectory, length) + L"\\Npcap\\wpcap.dll";
		// the altered search path makes wpcap.dll find Packet.dll in its own folder
		HMODULE library = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
		if (library == nullptr)
		{
			throw CaptureError("Npcap is not installed (System32\\Npcap\\wpcap.dll not found). "
				"Install it from https://npcap.com");
		}
		loadFunction(library, loaded.findalldevs, "pcap_findalldevs");
		loadFunction(library, loaded.freealldevs, "pcap_freealldevs");
		loadFunction(library, loaded.openLive, "pcap_open_live");
		loadFunction(library, loaded.openOffline, "pcap_open_offline");
		loadFunction(library, loaded.nextEx, "pcap_next_ex");
		loadFunction(library, loaded.datalink, "pcap_datalink");
		loadFunction(library, loaded.compile, "pcap_compile");
		loadFunction(library, loaded.setfilter, "pcap_setfilter");
		loadFunction(library, loaded.freecode, "pcap_freecode");
		loadFunction(library, loaded.geterr, "pcap_geterr");
		loadFunction(library, loaded.close, "pcap_close");
		loadFunction(library, loaded.libVersion, "pcap_lib_version");
#else
		loaded.findalldevs = &::pcap_findalldevs;
		loaded.freealldevs = &::pcap_freealldevs;
		loaded.openLive = &::pcap_open_live;
		loaded.openOffline = &::pcap_open_offline;
		loaded.nextEx = &::pcap_next_ex;
		loaded.datalink = &::pcap_datalink;
		loaded.compile = &::pcap_compile;
		loaded.setfilter = &::pcap_setfilter;
		loaded.freecode = &::pcap_freecode;
		loaded.geterr = &::pcap_geterr;
		loaded.close = &::pcap_close;
		loaded.libVersion = &::pcap_lib_version;
#endif
		return loaded;
	}();
	return api;
}

/**
 * WHAT:   Converts a socket address to text, if it is IPv4 or IPv6.
 * WHY:    Interfaces also have link-layer addresses that are not useful here.
 * RETURN: the address, or "" for other families
 *
 * @param address the socket address from pcap_findalldevs
 * @return the address as text
 */
std::string addressToString(const sockaddr* address)
{
	if (address == nullptr)
	{
		return "";
	}
	if (address->sa_family == AF_INET)
	{
		Ipv4Address ip{};
		std::memcpy(ip.data(), &reinterpret_cast<const sockaddr_in*>(address)->sin_addr, ip.size());
		return toString(ip);
	}
	if (address->sa_family == AF_INET6)
	{
		Ipv6Address ip{};
		std::memcpy(ip.data(), &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr, ip.size());
		return toString(ip);
	}
	return "";
}

} // namespace

std::vector<Device> Capture::listDevices()
{
	const PcapApi& api = pcapApi();
	char error[PCAP_ERRBUF_SIZE] = {};
	pcap_if_t* all = nullptr;
	if (api.findalldevs(&all, error) != 0)
	{
		throw CaptureError(std::string("could not list interfaces: ") + error);
	}

	std::vector<Device> devices;
	for (pcap_if_t* item = all; item != nullptr; item = item->next)
	{
		Device device;
		device.name = item->name;
		device.description = item->description != nullptr ? item->description : "";
		device.loopback = (item->flags & PCAP_IF_LOOPBACK) != 0;
		for (pcap_addr_t* address = item->addresses; address != nullptr; address = address->next)
		{
			std::string text = addressToString(address->addr);
			if (!text.empty())
			{
				device.addresses.push_back(std::move(text));
			}
		}
		devices.push_back(std::move(device));
	}
	api.freealldevs(all);
	return devices;
}

Capture Capture::openLive(const std::string& device, int snapLength, bool promiscuous, int timeoutMs)
{
	char error[PCAP_ERRBUF_SIZE] = {};
	pcap_t* handle = pcapApi().openLive(device.c_str(), snapLength, promiscuous ? 1 : 0, timeoutMs, error);
	if (handle == nullptr)
	{
		throw CaptureError(std::string("could not open interface: ") + error);
	}
	return Capture(handle);
}

Capture Capture::openFile(const std::string& path)
{
	char error[PCAP_ERRBUF_SIZE] = {};
	pcap_t* handle = pcapApi().openOffline(path.c_str(), error);
	if (handle == nullptr)
	{
		throw CaptureError(std::string("could not read file: ") + error);
	}
	return Capture(handle);
}

Capture::Capture(::pcap* handle) : handle_(handle)
{
}

Capture::Capture(Capture&& other) noexcept : handle_(std::exchange(other.handle_, nullptr))
{
}

Capture& Capture::operator=(Capture&& other) noexcept
{
	if (this != &other)
	{
		if (handle_ != nullptr)
		{
			pcapApi().close(handle_);
		}
		handle_ = std::exchange(other.handle_, nullptr);
	}
	return *this;
}

Capture::~Capture()
{
	if (handle_ != nullptr)
	{
		pcapApi().close(handle_);
	}
}

void Capture::setFilter(const std::string& expression)
{
	const PcapApi& api = pcapApi();
	bpf_program program{};
	if (api.compile(handle_, &program, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0)
	{
		throw CaptureError(std::string("invalid filter: ") + api.geterr(handle_));
	}
	const int result = api.setfilter(handle_, &program);
	api.freecode(&program);
	if (result != 0)
	{
		throw CaptureError(std::string("could not apply filter: ") + api.geterr(handle_));
	}
}

int Capture::dataLink() const
{
	return pcapApi().datalink(handle_);
}

ReadResult Capture::next(RawPacket& packet)
{
	const PcapApi& api = pcapApi();
	pcap_pkthdr* header = nullptr;
	const u_char* data = nullptr;
	const int result = api.nextEx(handle_, &header, &data);

	if (result == 0)
	{
		return ReadResult::Timeout;
	}
	if (result == PCAP_ERROR_BREAK)
	{
		return ReadResult::End;
	}
	if (result != 1)
	{
		throw CaptureError(std::string("read failed: ") + api.geterr(handle_));
	}

	packet.seconds = static_cast<std::int64_t>(header->ts.tv_sec);
	packet.microseconds = static_cast<std::int64_t>(header->ts.tv_usec);
	packet.originalLength = header->len;
	// the library reuses its buffer on the next call, so copy the bytes out
	packet.data.assign(data, data + header->caplen);
	return ReadResult::Packet;
}

std::string Capture::libraryVersion()
{
	return pcapApi().libVersion();
}

} // namespace wiresight
