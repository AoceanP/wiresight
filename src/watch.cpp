#include "watch.hpp"

#include <algorithm>
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
constexpr Rgb CLOSED = {72, 44, 50};
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

/** WHAT: a number with thousands separators; defined below. */
std::string grouped(std::size_t value);

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
 * @param probes    SYNs sent so far, shown on the label
 * @param answers   answers received so far, shown on the label
 * @return the wire text
 */
std::string wireLine(int line, int tick, bool probing, bool answering, Rgb answer, std::size_t probes,
	std::size_t answers)
{
	if (line == 1)
	{
		const std::string count = grouped(probes);
		return std::format("{} SYN probes → {}{}{}{}", fg(DIM), fg(AMBER), count, RESET,
			std::string(static_cast<std::size_t>(WIRE_W - 14) - std::min<std::size_t>(count.size(), WIRE_W - 14), ' '));
	}
	if (line == 4)
	{
		const std::string count = grouped(answers);
		return std::format("{}{}{}{} ← answers {}",
			std::string(static_cast<std::size_t>(WIRE_W - 11) - std::min<std::size_t>(count.size(), WIRE_W - 11), ' '),
			fg(answers > 0 ? WHITE : DIM), count, fg(DIM), RESET);
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

namespace
{

/** WHAT: width inside the frame, in columns; the whole view is 78 wide, fitting an 80-column terminal. */
constexpr int INNER = 76;
/** WHAT: the frame's colour. */
constexpr Rgb BORDER = {70, 78, 92};
/** WHAT: background of the calm "no scan" bar. */
constexpr Rgb CALM_BG = {26, 58, 40};
/** WHAT: cells in the progress bar. */
constexpr int BAR_W = 32;

/**
 * WHAT:   How many columns text takes on screen.
 * WHY:    Escape codes take no space and each UTF-8 character takes one
 *         column (the view only uses single-width characters), so lines
 *         can be padded to line up with the frame.
 * RETURN: the visible width
 *
 * @param text text with escape codes
 * @return the width in columns
 */
int visibleWidth(std::string_view text)
{
	int width = 0;
	for (std::size_t i = 0; i < text.size(); ++i)
	{
		if (text[i] == '\x1b')
		{
			while (i < text.size() && !(text[i] >= '@' && text[i] <= '~' && text[i] != '['))
			{
				++i;
			}
			continue;
		}
		if ((static_cast<unsigned char>(text[i]) & 0xC0) != 0x80)
		{
			++width;
		}
	}
	return width;
}

/** WHAT: a frame character in the border colour. */
std::string edge(std::string_view glyph)
{
	return fg(BORDER) + std::string(glyph) + std::string(RESET);
}

/** WHAT: a horizontal run of the frame line. */
std::string rule(int width)
{
	std::string out;
	for (int i = 0; i < width; ++i)
	{
		out += "─";
	}
	return out;
}

/**
 * WHAT:   One line inside the frame: "│", the content padded to INNER, "│".
 *
 * @param content the line's content
 * @return the framed line, with END_LINE
 */
std::string boxed(const std::string& content)
{
	const int pad = std::max(0, INNER - visibleWidth(content));
	return edge("│") + content + std::string(RESET) + std::string(static_cast<std::size_t>(pad), ' ') + edge("│")
		+ std::string(END_LINE);
}

/**
 * WHAT:   A frame divider with a title, e.g. "├─ port map ────┤".
 *
 * @param left  "╭" or "├"
 * @param right "╮" or "┤"
 * @param title the title (may contain colour), or ""
 * @param note  text for the right end (may contain colour), or ""
 * @return the divider line, with END_LINE
 */
std::string divider(std::string_view left, std::string_view right, const std::string& title, const std::string& note)
{
	const std::string head = title.empty() ? "" : " " + title + " ";
	const std::string tail = note.empty() ? "" : " " + note + " ";
	const int fill = std::max(1, INNER - 1 - visibleWidth(head) - visibleWidth(tail) - (tail.empty() ? 0 : 1));
	return fg(BORDER) + std::string(left) + "─" + std::string(RESET) + head + fg(BORDER) + rule(fill) + std::string(RESET)
		+ tail + (tail.empty() ? "" : edge("─")) + edge(right) + std::string(END_LINE);
}

/**
 * WHAT:   A progress bar with eighth-cell precision.
 *
 * @param done   how many are done
 * @param total  how many there are
 * @param colour the bar's colour
 * @return BAR_W cells of bar
 */
std::string progressBar(std::size_t done, std::size_t total, Rgb colour)
{
	static constexpr std::string_view PARTS[] = {"", "▏", "▎", "▍", "▌", "▋", "▊", "▉"};
	const std::size_t eighths = total == 0 ? 0 : std::min(done, total) * BAR_W * 8 / total;
	std::string out = fg(colour) + bg(PANEL);
	for (std::size_t i = 0; i < eighths / 8; ++i)
	{
		out += "█";
	}
	int used = static_cast<int>(eighths / 8);
	if (used < BAR_W && eighths % 8 != 0)
	{
		out += PARTS[eighths % 8];
		++used;
	}
	out += std::string(static_cast<std::size_t>(BAR_W - used), ' ');
	return out + std::string(RESET);
}

/**
 * WHAT:   A labelled number, e.g. "OPEN 4", with the label dim and the number bold.
 *
 * @param label  the label
 * @param value  the number
 * @param colour the number's colour
 * @return the tile text
 */
std::string tile(std::string_view label, std::size_t value, Rgb colour)
{
	return std::format("{}{} {}\x1b[1m{}{}", fg(DIM), label, fg(colour), grouped(value), RESET);
}

/**
 * WHAT:   Text centred in a field, e.g. a label under a sprite.
 *
 * @param text  the text (no colour)
 * @param width the field width
 * @return the padded text
 */
std::string centred(const std::string& text, int width)
{
	const int left = std::max(0, (width - static_cast<int>(text.size())) / 2);
	return std::string(static_cast<std::size_t>(left), ' ') + text
		+ std::string(static_cast<std::size_t>(std::max(0, width - left - static_cast<int>(text.size()))), ' ');
}

} // namespace

std::string renderWatch(const ScanTrack* track, const WatchStatus& status, int tick)
{
	std::string out = "\x1b[H";

	// 1: title bar
	const Rgb badge = status.sourceLabel == "LIVE" ? GREEN : AMBER;
	out += divider("╭", "╮",
		std::format("\x1b[1m{}wiresight{} {}scan watch{}", fg(WHITE), RESET, fg(DIM), RESET),
		std::format("{}● {}{}  {}{} packets{}{}", fg(badge), status.sourceLabel, RESET, fg(DIM),
			grouped(status.packets), status.finished ? " · finished" : "", RESET));

	// 2-10: the scene: scanner, wire, target, and who is who
	const bool live = !status.finished && track != nullptr;
	const bool probing = live && status.nowMicros - track->lastProbeMicros < ACTIVE_MICROS;
	const bool answering = live && track->lastReplyMicros != 0 && status.nowMicros - track->lastReplyMicros < ACTIVE_MICROS;
	const Rgb answer = track != nullptr && track->lastReply == PortState::Open ? GREEN : RED;
	const std::size_t open = track != nullptr ? track->count(PortState::Open) : 0;
	const std::size_t closed = track != nullptr ? track->count(PortState::Closed) : 0;
	const std::size_t silent = track != nullptr ? track->count(PortState::Probed) : 0;
	const Lights lights{
		.cursor = tick % 6 < 3,
		.probed = probing && tick % 2 == 0,
		.open = open > 0,
		.alarm = track != nullptr && track->alerted && (status.finished || tick % 4 < 2),
	};
	const std::string side = "    ";
	out += boxed("");
	for (int line = 0; line < SPRITE_H / 2; ++line)
	{
		out += boxed(side + spriteLine(SCANNER_ART, line, lights, true) + "   "
			+ wireLine(line, tick, probing, answering, answer, track != nullptr ? track->probes : 0, open + closed) + "   "
			+ spriteLine(SERVER_ART, line, lights, false));
	}
	const int gap = 3 + WIRE_W + 3;
	out += boxed(std::format("{}{}{}{}{}{}", side, fg(DIM), centred("scanner", SPRITE_W), std::string(static_cast<std::size_t>(gap), ' '),
		centred("target", SPRITE_W), RESET));
	const std::string source = track != nullptr ? track->source : "-";
	const std::string target = track != nullptr ? track->target : "-";
	out += boxed(std::format("{}\x1b[1m{}{}{}{}\x1b[1m{}{}{}", side.substr(0, 2), fg(AMBER), centred(source, SPRITE_W + 4), RESET,
		std::string(static_cast<std::size_t>(gap - 4), ' '), fg(WHITE), centred(target, SPRITE_W + 4), RESET));

	// 11-20: the port map
	out += divider("├", "┤", std::format("{}port map{}", fg(WHITE), RESET),
		std::format("{}ports 1-1024, one pixel each{}", fg(DIM), RESET));
	for (int line = 0; line < GRID_H / 2; ++line)
	{
		std::string row = "  ";
		for (int x = 0; x < GRID_W; ++x)
		{
			const auto top = static_cast<std::uint16_t>(line * 2 * GRID_W + x + 1);
			const auto bottom = static_cast<std::uint16_t>(top + GRID_W);
			row += cell(portColour(track, top), portColour(track, bottom));
		}
		const int first = line * 2 * GRID_W + 1;
		out += boxed(row + std::format("{} {}{:>8} ", RESET, fg(DIM), std::format("{}-{}", first, first + 2 * GRID_W - 1)));
	}
	out += boxed(std::format("  {} not probed  {} no answer  {} closed  {} open  {} newest probe", swatch(PANEL),
		swatch(AMBER), swatch(CLOSED), swatch(GREEN), swatch(WHITE)));

	// 21-25: the numbers
	out += divider("├", "┤", std::format("{}result{}", fg(WHITE), RESET), "");
	std::size_t inMap = 0;
	std::size_t above = 0;
	std::string openList;
	std::size_t openShown = 0;
	if (track != nullptr)
	{
		for (const auto& [port, state] : track->ports)
		{
			(port <= GRID_PORTS ? inMap : above) += 1;
			if (state == PortState::Open && openShown++ < 6)
			{
				const std::string name = serviceName(port);
				openList += std::format("  {}\x1b[1m{}{}{}{}", fg(GREEN), port, RESET, name.empty() ? "" : " ", name);
			}
		}
	}
	out += boxed(std::format("  {}PROBED{} {}  {}\x1b[1m{}{} / 1,024", fg(DIM), RESET,
		progressBar(inMap, GRID_PORTS, inMap == static_cast<std::size_t>(GRID_PORTS) ? GREEN : AMBER), fg(WHITE),
		grouped(inMap), RESET));
	out += boxed(std::format("  {}    {}    {}    {}", tile("OPEN", open, GREEN), tile("CLOSED", closed, RED),
		tile("NO ANSWER", silent, AMBER), tile("ABOVE 1024", above, WHITE)));
	if (track == nullptr)
	{
		out += boxed(std::format("  {}no TCP connection attempts seen yet{}", fg(DIM), RESET));
	}
	else if (open == 0)
	{
		out += boxed(std::format("  {}open ports: none found yet{}", fg(DIM), RESET));
	}
	else
	{
		out += boxed(std::format("  {}open ports:{}{}{}", fg(DIM), RESET, openList,
			open > openShown ? std::format("  {}+{} more{}", fg(DIM), open - openShown, RESET) : ""));
	}
	out += fg(BORDER) + "╰" + rule(INNER) + "╯" + std::string(END_LINE);

	// 26-27: the verdict, as a full-width bar
	std::string verdict;
	Rgb verdictBg = CALM_BG;
	if (status.alert)
	{
		const ScanAlert& alert = *status.alert;
		verdictBg = ALARM_BG;
		verdict = std::format("\x1b[1m PORT SCAN DETECTED \x1b[22m  {} → {}  ·  {} different ports in {:.1f} s",
			alert.source, alert.target, alert.ports, static_cast<double>(alert.elapsedMicros) / 1e6);
	}
	else
	{
		verdict = " ✓ no scan detected  ·  watching for one address probing many ports";
	}
	const int verdictPad = std::max(0, INNER + 2 - visibleWidth(verdict));
	out += bg(verdictBg) + fg(WHITE) + verdict + std::string(static_cast<std::size_t>(verdictPad), ' ') + std::string(END_LINE);
	out += std::format(" {}{}{}", fg(DIM), status.finished ? "finished; this frame stays on screen" : "Ctrl+C to stop", END_LINE);
	return out;
}

} // namespace wiresight
