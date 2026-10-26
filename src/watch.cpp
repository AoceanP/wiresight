#include "watch.hpp"

#include <array>
#include <format>
#include <string_view>

namespace wiresight
{

namespace
{

/** WHAT: a 24-bit colour. */
struct Rgb
{
	std::uint8_t r;
	std::uint8_t g;
	std::uint8_t b;
};

// the palette: dark slate scenery, amber for probes, green for open, red for alarm
constexpr Rgb FRAME = {107, 116, 132};
constexpr Rgb SCREEN = {27, 32, 41};
constexpr Rgb TEXT_GREEN = {91, 211, 138};
constexpr Rgb AMBER = {232, 154, 60};
constexpr Rgb SILVER = {154, 163, 177};
constexpr Rgb PANEL = {43, 49, 60};
constexpr Rgb VENT = {61, 69, 82};
constexpr Rgb LED_OFF = {58, 66, 80};
constexpr Rgb GREEN = {70, 208, 122};
constexpr Rgb RED = {224, 96, 90};
constexpr Rgb DIM = {120, 128, 140};
constexpr Rgb WHITE = {245, 245, 240};
constexpr Rgb CLOSED = {86, 50, 55};
constexpr Rgb ALARM_BG = {176, 52, 48};

/** WHAT: sprite size in pixels; two pixel rows make one text line. */
constexpr int SPRITE_W = 16;
constexpr int SPRITE_H = 12;
/** WHAT: the wire between the sprites, in text columns. */
constexpr int WIRE_W = 32;
/** WHAT: the port map: 64 x 16 pixels = ports 1 to 1024. */
constexpr int GRID_W = 64;
constexpr int GRID_H = 16;
constexpr int GRID_PORTS = GRID_W * GRID_H;
/** WHAT: a probe or answer this recent makes the wire animate. */
constexpr std::int64_t ACTIVE_MICROS = 400'000;

/** WHAT: the scanner: a monitor with a terminal on it. '1' is the blinking cursor. */
constexpr std::array<std::string_view, SPRITE_H> SCANNER_ART = {
	"................",
	".kkkkkkkkkkkkkk.",
	".kddddddddddddk.",
	".kdggdgggggdddk.",
	".kddddddddddddk.",
	".kdgggdggdgggdk.",
	".kddddddddddddk.",
	".kdg1dddddddddk.",
	".kddddddddddddk.",
	".kkkkkkkkkkkkkk.",
	"......kkkk......",
	"....kkkkkkkk....",
};

/** WHAT: the target: a two-unit server. LEDs 1 power, 2 probed, 3 open port, 4 alarm. */
constexpr std::array<std::string_view, SPRITE_H> SERVER_ART = {
	"................",
	"..ssssssssssss..",
	"..sKKKKKKKKKKs..",
	"..sK1K2KvvvvKs..",
	"..sKKKKKKKKKKs..",
	"..ssssssssssss..",
	"..sKKKKKKKKKKs..",
	"..sK3K4KvvvvKs..",
	"..sKKKKKKKKKKs..",
	"..ssssssssssss..",
	"...ss......ss...",
	"................",
};

/**
 * WHAT:   Checks at compile time that every sprite row has the same width.
 * RETURN: true if all rows are SPRITE_W wide
 *
 * @param art the sprite rows
 * @return whether the sprite is rectangular
 */
constexpr bool rectangular(const std::array<std::string_view, SPRITE_H>& art)
{
	for (const std::string_view row : art)
	{
		if (row.size() != static_cast<std::size_t>(SPRITE_W))
		{
			return false;
		}
	}
	return true;
}
static_assert(rectangular(SCANNER_ART) && rectangular(SERVER_ART), "sprite rows must be 16 pixels wide");

/** WHAT: "set text colour". */
std::string fg(Rgb c)
{
	return std::format("\x1b[38;2;{};{};{}m", c.r, c.g, c.b);
}

/** WHAT: "set background colour". */
std::string bg(Rgb c)
{
	return std::format("\x1b[48;2;{};{};{}m", c.r, c.g, c.b);
}

/** WHAT: back to the terminal's own colours. */
constexpr std::string_view RESET = "\x1b[0m";
/** WHAT: end of a line: reset, clear the rest of the old frame's line, newline. */
constexpr std::string_view END_LINE = "\x1b[0m\x1b[K\n";

/**
 * WHAT:   Draws two pixels in one text cell with the upper-half block.
 * WHY:    A terminal cell is about twice as tall as wide, so splitting it
 *         gives two square pixels: text colour on top, background below.
 *         A missing pixel shows the terminal's own background.
 * RETURN: the escape codes and character for the cell
 *
 * @param top    upper pixel, or nothing
 * @param bottom lower pixel, or nothing
 * @return the cell text
 */
std::string cell(std::optional<Rgb> top, std::optional<Rgb> bottom)
{
	if (!top && !bottom)
	{
		return std::string(RESET) + " ";
	}
	if (!top)
	{
		return std::string(RESET) + fg(*bottom) + "▄"; // lower half block
	}
	if (!bottom)
	{
		return std::string(RESET) + fg(*top) + "▀"; // upper half block
	}
	return fg(*top) + bg(*bottom) + "▀";
}

/** WHAT: what changes in the sprites from frame to frame. */
struct Lights
{
	bool cursor;
	bool probed;
	bool open;
	bool alarm;
};

/**
 * WHAT:   The colour of one sprite pixel.
 * RETURN: the colour, or nothing for a see-through pixel
 *
 * @param code   the character in the sprite
 * @param lights the current LED and cursor states
 * @return the colour
 */
std::optional<Rgb> spriteColour(char code, const Lights& lights)
{
	switch (code)
	{
	case 'k': return FRAME;
	case 'd': return SCREEN;
	case 'g': return TEXT_GREEN;
	case 's': return SILVER;
	case 'K': return PANEL;
	case 'v': return VENT;
	case '1': return GREEN; // scanner cursor shares '1' with the server's power LED
	case '2': return lights.probed ? AMBER : LED_OFF;
	case '3': return lights.open ? GREEN : LED_OFF;
	case '4': return lights.alarm ? RED : LED_OFF;
	default: return std::nullopt;
	}
}

/**
 * WHAT:   One text line (two pixel rows) of a sprite.
 * RETURN: SPRITE_W cells
 *
 * @param art    the sprite
 * @param line   the text line, 0 to SPRITE_H / 2 - 1
 * @param lights the current light states
 * @param cursor whether code '1' is a blinking cursor (scanner) rather than a steady LED
 * @return the cells
 */
std::string spriteLine(const std::array<std::string_view, SPRITE_H>& art, int line, const Lights& lights, bool cursor)
{
	std::string out;
	for (int x = 0; x < SPRITE_W; ++x)
	{
		const auto colour = [&](int y) -> std::optional<Rgb> {
			const char code = art[static_cast<std::size_t>(y)][static_cast<std::size_t>(x)];
			if (cursor && code == '1')
			{
				return lights.cursor ? AMBER : SCREEN;
			}
			return spriteColour(code, lights);
		};
		out += cell(colour(line * 2), colour(line * 2 + 1));
	}
	return out + std::string(RESET);
}

/**
 * WHAT:   One text line of the wire between the machines.
 * WHY:    Probes move right on the upper lane and answers move left on the
 *         lower lane, coloured by what they said, so the conversation
 *         reads like the diagram in a networking textbook.
 * RETURN: WIRE_W columns
 *
 * @param line      0 to 5
 * @param tick      animation step
 * @param probing   SYNs are arriving now
 * @param answering answers are arriving now
 * @param answer    colour of the latest answer
 * @return the wire text
 */
std::string wireLine(int line, int tick, bool probing, bool answering, Rgb answer)
{
	if (line == 1)
	{
		return fg(DIM) + std::format("{:<{}}", " SYN probes →", WIRE_W) + std::string(RESET);
	}
	if (line == 4)
	{
		return fg(DIM) + std::format("{:>{}}", "← answers ", WIRE_W) + std::string(RESET);
	}
	if (line != 2 && line != 3)
	{
		return std::string(WIRE_W, ' ');
	}

	const bool active = line == 2 ? probing : answering;
	std::array<bool, WIRE_W> dot{};
	if (active)
	{
		for (int i = 0; i < 4; ++i)
		{
			const int step = (tick * 2 + i * 8 + (line == 3 ? 4 : 0)) % WIRE_W;
			dot[static_cast<std::size_t>(line == 2 ? step : WIRE_W - 1 - step)] = true;
		}
	}
	std::string out;
	for (int x = 0; x < WIRE_W; ++x)
	{
		out += dot[static_cast<std::size_t>(x)] ? fg(line == 2 ? AMBER : answer) + "●" : fg(PANEL) + "─";
	}
	return out + std::string(RESET);
}

/**
 * WHAT:   The colour of one port in the map.
 * RETURN: the colour for its state; the newest probe flashes white
 *
 * @param track the scan, or nullptr
 * @param port  the port number
 * @return the colour
 */
Rgb portColour(const ScanTrack* track, std::uint16_t port)
{
	if (track == nullptr)
	{
		return PANEL;
	}
	if (!track->recent.empty() && track->recent.back().second == port)
	{
		return WHITE;
	}
	const auto found = track->ports.find(port);
	if (found == track->ports.end())
	{
		return PANEL;
	}
	switch (found->second)
	{
	case PortState::Probed: return AMBER;
	case PortState::Closed: return CLOSED;
	case PortState::Open: return GREEN;
	default: return PANEL;
	}
}

/** WHAT: a two-cell colour sample for the legend. */
std::string swatch(Rgb c)
{
	return fg(c) + "██" + std::string(RESET);
}

/** WHAT: a number with thousands separators, e.g. 12,345. */
std::string grouped(std::size_t value)
{
	std::string digits = std::to_string(value);
	for (int i = static_cast<int>(digits.size()) - 3; i > 0; i -= 3)
	{
		digits.insert(static_cast<std::size_t>(i), ",");
	}
	return digits;
}

} // namespace

std::string serviceName(std::uint16_t port)
{
	switch (port)
	{
	case 21: return "ftp";
	case 22: return "ssh";
	case 23: return "telnet";
	case 25: return "smtp";
	case 53: return "dns";
	case 80: return "http";
	case 110: return "pop3";
	case 135: return "rpc";
	case 139: return "netbios";
	case 143: return "imap";
	case 443: return "https";
	case 445: return "smb";
	case 993: return "imaps";
	case 995: return "pop3s";
	case 3306: return "mysql";
	case 3389: return "rdp";
	case 8080: return "http-alt";
	default: return "";
	}
}

std::string renderWatch(const ScanTrack* track, const WatchStatus& status, int tick)
{
	std::string out = "\x1b[H";

	// 1-2: title, source and packet count
	const Rgb badge = status.sourceLabel == "LIVE" ? GREEN : AMBER;
	out += std::format("  \x1b[1m{}wiresight{}  {}scan watch{}      {}● {}{}  {}{} packets{}{}",
		fg(WHITE), RESET, fg(DIM), RESET, fg(badge), status.sourceLabel, RESET, fg(DIM),
		grouped(status.packets), status.finished ? " · finished" : "", END_LINE);
	out += END_LINE;

	// 3-8: the scene
	const bool live = !status.finished && track != nullptr;
	const bool probing = live && status.nowMicros - track->lastProbeMicros < ACTIVE_MICROS;
	const bool answering = live && track->lastReplyMicros != 0 && status.nowMicros - track->lastReplyMicros < ACTIVE_MICROS;
	const Rgb answer = track != nullptr && track->lastReply == PortState::Open ? GREEN : RED;
	const Lights lights{
		.cursor = tick % 6 < 3,
		.probed = probing && tick % 2 == 0,
		.open = track != nullptr && track->count(PortState::Open) > 0,
		.alarm = track != nullptr && track->alerted && (status.finished || tick % 4 < 2),
	};
	for (int line = 0; line < SPRITE_H / 2; ++line)
	{
		out += "  " + spriteLine(SCANNER_ART, line, lights, true) + "  " + wireLine(line, tick, probing, answering, answer)
			+ "  " + spriteLine(SERVER_ART, line, lights, false) + std::string(END_LINE);
	}

	// 9-10: who is who
	const int targetColumn = SPRITE_W + 2 + WIRE_W + 2;
	out += std::format("  {}{:<{}}{}{}", fg(DIM), "scanner", targetColumn, "target", END_LINE);
	const std::string source = track != nullptr ? track->source : "-";
	const std::string target = track != nullptr ? track->target : "-";
	out += std::format("  {}\x1b[1m{:<{}}{}\x1b[1m{}{}", fg(AMBER), source, targetColumn, fg(WHITE), target, END_LINE);
	out += END_LINE;

	// 12-21: the port map and its legend
	out += std::format("  {}ports 1 to 1024 on the target, one pixel per port{}", fg(DIM), END_LINE);
	for (int line = 0; line < GRID_H / 2; ++line)
	{
		out += "  ";
		for (int x = 0; x < GRID_W; ++x)
		{
			const auto top = static_cast<std::uint16_t>(line * 2 * GRID_W + x + 1);
			const auto bottom = static_cast<std::uint16_t>(top + GRID_W);
			out += cell(portColour(track, top), portColour(track, bottom));
		}
		const int first = line * 2 * GRID_W + 1;
		out += std::format("{} {}{:>4}-{}{}", RESET, fg(DIM), first, first + 2 * GRID_W - 1, END_LINE);
	}
	out += std::format("  {} not probed   {} no answer yet   {} closed   {} open   {} newest probe{}",
		swatch(PANEL), swatch(AMBER), swatch(CLOSED), swatch(GREEN), swatch(WHITE), END_LINE);
	out += END_LINE;

	// 23-24: counts and open ports
	if (track == nullptr)
	{
		out += std::format("  {}no TCP connection attempts seen yet{}", fg(DIM), END_LINE);
		out += END_LINE;
	}
	else
	{
		std::size_t inMap = 0;
		std::size_t above = 0;
		std::string open;
		std::size_t openShown = 0;
		for (const auto& [port, state] : track->ports)
		{
			(port <= GRID_PORTS ? inMap : above) += 1;
			if (state == PortState::Open && openShown++ < 8)
			{
				const std::string name = serviceName(port);
				open += std::format("  {}{}{}{}{}", fg(GREEN), port, RESET, name.empty() ? "" : " ", name);
			}
		}
		const std::size_t openCount = track->count(PortState::Open);
		out += std::format("  probed {}{}{} of 1024   open {}{}{}   closed {}   no answer {}{}{}   above 1024: {}{}",
			fg(AMBER), inMap, RESET, fg(GREEN), openCount, RESET, track->count(PortState::Closed), fg(AMBER),
			track->count(PortState::Probed), RESET, above, END_LINE);
		if (openCount == 0)
		{
			out += std::format("  {}open: none found yet{}", fg(DIM), END_LINE);
		}
		else
		{
			out += std::format("  open:{}{}{}", open, openCount > openShown ? std::format("  +{} more", openCount - openShown) : "",
				END_LINE);
		}
	}
	out += END_LINE;

	// 26-27: the verdict
	if (status.alert)
	{
		const ScanAlert& alert = *status.alert;
		out += std::format("  {}{}\x1b[1m PORT SCAN {}  {}\x1b[1m{}{} → {}\x1b[1m{}{}   {}alarm raised after {} different ports in {:.1f} s{}",
			bg(ALARM_BG), fg(WHITE), RESET, fg(RED), alert.source, RESET, fg(WHITE), alert.target, RESET, fg(DIM),
			alert.ports, static_cast<double>(alert.elapsedMicros) / 1e6, END_LINE);
	}
	else
	{
		out += std::format("  {}✓ no scan detected{}  {}(watching for one address probing many ports){}", fg(GREEN),
			RESET, fg(DIM), END_LINE);
	}
	out += std::format("  {}{}{}", fg(DIM), status.finished ? "finished; this frame stays on screen" : "Ctrl+C to stop",
		END_LINE);
	return out;
}

} // namespace wiresight
