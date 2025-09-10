/* draw.c */

/*
 * Copyright (C) 2025, Leo Abramovich <leo.clifm@outlook.com>
 * All rights reserved.

* The MIT License (MIT)

* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

/* Expose PATH_MAX, and wcswidth */
#define _XOPEN_SOURCE 700

#include <string.h> /* memset, strlen */
#include <stdlib.h> /* mbstowcs, free */
#include <stdint.h> /* uint8_t */
#include <limits.h> /* PATH_MAX */
#include <wchar.h>  /* wcswidth */

#include "keypress.h" /* BUF_SIZE, PROG_NAME, VERSION, get_term_type */
#include "options.h" /* g_options */
#include "term.h" /* CLEAR_SCREEN */
#include "translate_key.h" /* translate_key */

#define IS_DIGIT(n) ((n) >= '0' && (n) <= '9')

/* Lenght of the table, excluding borders. */
#define TABLE_WIDTH 35

#define SEP_U "│"
#define SEP_A "|"

#define BOTTOM_CLR_U    "└──────┴──────┴─────┴──────────┴──────┘"
#define BOTTOM_NO_CLR_U "├──────┼──────┼─────┼──────────┼──────┤"
#define BOTTOM_CLR_A    "+------+------+-----+----------+------+"
#define BOTTOM_NO_CLR_A "+------+------+-----+----------+------+"

#define HEADER_TOP_U  "┌──────┬──────┬─────┬──────────┬──────┐"
#define HEADER_BASE_U "├──────┼──────┼─────┼──────────┼──────┤"
#define HEADER_TOP_A  "+-------------------------------------+"
#define HEADER_BASE_A "+------+------+-----+----------+------+"

#define FOOTER_TOP_U         "├──────┴──────┴─────┴──────────┴──────┤"
#define FOOTER_BASE_CLR_U    "└─────────────────────────────────────┘"
#define FOOTER_BASE_NO_CLR_U "├─────────────────────────────────────┤"
#define FOOTER_TOP_A         "+-------------------------------------+"
#define FOOTER_BASE_CLR_A    "+-------------------------------------+"
#define FOOTER_BASE_NO_CLR_A "+-------------------------------------+"

static size_t
wc_xstrlen(const char *restrict str)
{
	wchar_t wbuf[PATH_MAX];
	const size_t len = mbstowcs(wbuf, str, (size_t)PATH_MAX);
	if (len == (size_t)-1) /* Invalid multi-byte sequence found */
		return 0;

	const int width = wcswidth(wbuf, len);
	if (width != -1)
		return (size_t)width;

	return 0; /* A non-printable wide char was found */
}

/* Return a pointer to a string holding the binary representation
 * of the byte N. */
static char *
build_binary(const uint8_t n)
{
	static char bin[9] = {0};

	for (int i = 0; i < 8; i++)
		bin[7 - i] = (n & (1u << i)) ? '1' : '0';
	bin[8] = '\0';

	return bin;
}

struct ticaps_t {
	const char *name;
	const char *ticap;
};

/* Map key translations to terminfo capabilty names. */
static struct ticaps_t ticaps[] = {
	/* Function keys */
	{"F1", "kf1"}, {"F2", "kf2"}, {"F3", "kf3"}, {"F4", "kf4"}, {"F5", "kf5"},
	{"F6", "kf6"}, {"F7", "kf7"}, {"F8", "kf8"}, {"F9", "kf9"}, {"F10", "kf10"},
	{"F11", "kf11"}, {"F12", "kf12"}, {"Menu", "kf16"},

	/* Arrow keys */
	{"Down", "kcud1"}, {"Left", "kcub1"}, {"Right", "kcuf1"}, {"Up", "kcuu1"},

	/* Editing keys */
	{"Home", "khome"}, {"Insert", "kich1"}, {"PgDn", "knp"}, {"PgUp", "kpp"},
	{"Begin", "kbeg"}, {"Delete", "kdch1"}, {"End", "kend"},

	/* Keypad keys */
	{"KP_Home", "ka1"}, {"KP_PgUp", "ka3"},
	{"KP_Begin", "kb2"},
	{"KP_End", "kc1"}, {"KP_PgDn", "kc3"},
	{"KP_Enter", "kent"},

	/* Shifted keys */
	/* These two are inverted in Rxvt compared to Xterm. */
	{"Shift+Up", "kri"}, {"Shift+Down", "kind"},

	{"Shift+Right", "kRIT"}, {"Shift+PgDn", "kNXT"}, {"Shift+PgUp", "kPRV"},
	{"Shift+Left", "kLFT"}, {"Shift+Home", "kHOM"}, {"Shift+End", "kEND"},
	{"Shift+Begin", "kBEG"}, {"Shift+Delete", "kDC"}, {"Shift+Insert", "kIC"},

	/* Misc keys */
	{"Backspace", "kbs"}, {"Shift+Tab", "kcbt"},

	/* Modified function keys
	 * Based on xterm values. For rxvt-based terminals we need to hack
	 * some of these values. See build_ticap() below. */
	{"Shift+F1", "kf13"}, {"Shift+F2", "kf14"}, {"Shift+F3", "kf15"},
	{"Shift+F4", "kf16"}, {"Shift+F5", "kf17"}, {"Shift+F6", "kf18"},
	{"Shift+F7", "kf19"}, {"Shift+F8", "kf20"}, {"Shift+F9", "kf21"},
	{"Shift+F10", "kf22"}, {"Shift+F11", "kf23"}, {"Shift+F12", "kf24"},

	{"Ctrl+F1", "kf25"}, {"Ctrl+F2", "kf26"}, {"Ctrl+F3", "kf27"},
	{"Ctrl+F4", "kf28"}, {"Ctrl+F5", "kf29"}, {"Ctrl+F6", "kf30"},
	{"Ctrl+F7", "kf31"}, {"Ctrl+F8", "kf32"}, {"Ctrl+F9", "kf33"},
	{"Ctrl+F10", "kf34"}, {"Ctrl+F11", "kf35"}, {"Ctrl+F12", "kf36"},

	{"Ctrl+Shift+F1", "kf37"}, {"Ctrl+Shift+F2", "kf38"},
	{"Ctrl+Shift+F3", "kf39"}, {"Ctrl+Shift+F4", "kf40"},
	{"Ctrl+Shift+F5", "kf41"}, {"Ctrl+Shift+F6", "kf42"},
	{"Ctrl+Shift+F7", "kf43"}, {"Ctrl+Shift+F8", "kf44"},
	{"Ctrl+Shift+F9", "kf45"}, {"Ctrl+Shift+F10", "kf46"},
	{"Ctrl+Shift+F11", "kf47"}, {"Ctrl+Shift+F12", "kf48"},

	{"Alt+F1", "kf49"}, {"Alt+F2", "kf50"}, {"Alt+F3", "kf51"},
	{"Alt+F4", "kf52"}, {"Alt+F5", "kf53"}, {"Alt+F6", "kf54"},
	{"Alt+F7", "kf55"}, {"Alt+F8", "kf56"}, {"Alt+F9", "kf57"},
	{"Alt+F10", "kf58"}, {"Alt+F11", "kf59"}, {"Alt+F12", "kf60"},

	{"Alt+Shift+F1", "kf61"}, {"Alt+Shift+F2", "kf62"}, {"Alt+Shift+F3", "kf63"},

	{NULL, NULL}
};

static const char *
build_ticap(const char *str)
{
	char *p = g_is_rxvt == 1 ? strrchr(str, '+') : NULL;
	int diff = (p && p[1] == 'F' && IS_DIGIT(p[2])) ? 2 : 0; // Rxvt
	if (diff > 0 && strncmp(str, "Ctrl+Shift+F", 12) == 0)
		diff += 2;

	int found = -1;
	for (int i = 0; ticaps[i].name; i++) {
		if (*str == *ticaps[i].name && strcmp(str, ticaps[i].name) == 0) {
			/* The values of kri and kind and inverted in Rxvt regarding Xterm. */
			if (g_is_rxvt == 1 && strcmp(ticaps[i].ticap, "kri") == 0)
				/* kind is the next one in the ticaps table */
				found = i + 1;
			else if (g_is_rxvt == 1 && strcmp(ticaps[i].ticap, "kind") == 0)
				/* kri is the previous one in the ticaps table */
				found = i > 0 ? i - 1 : i;
			else
				found = i;
			break;
		}
	}

	if (diff > 0) { // Rxvt reports kf[1-44].
		const char *t = found >= diff ? ticaps[found - diff].ticap : NULL;
		if (t && *t == 'k' && t[1] == 'f' && atoi(t + 2) > 44)
			return "";
	}

	if (found != -1) {
		static char buf[32];
		snprintf(buf, sizeof(buf), "%s (%s)",
			g_options.colors.reset, ticaps[found - diff].ticap);
		return buf;
	}

	return "";
}

/* Return the number of bytes of a character by inspecting
 * its initial byte (C). */
int
utf8_char_bytes(unsigned char c)
{
	if (c < 0x80) return 1;           /* ASCII */
	if ((c & 0xE0) == 0xC0) return 2; /* 110xxxxx */
	if ((c & 0xF0) == 0xE0) return 3; /* 1110xxxx */
	if ((c & 0xF8) == 0xF0) return 4; /* 11110xxx */
	return 0;                         /* Continuation (10xxxxxx) or invalid */
}

/* Set CP_OUT to the codepoint corresponding to the UTF-8 character S.
 * Returns 1 on success or 0 on failure. */
static int
utf8_decode(const unsigned char *s, uint32_t *cp_out)
{
	unsigned char b0 = s[0];

	const int bytes = utf8_char_bytes(b0);
	if (bytes == 0)
		return 1;

	if (bytes == 1) { /* 1-byte ASCII */
		*cp_out = b0;
		return 0;
	}

	if (bytes == 2 && s[1]) {
		unsigned char b1 = s[1];
		if ((b1 & 0xc0) != 0x80)
			return 1;
		uint32_t cp = (uint32_t)(((b0 & 0x1f) << 6) | (b1 & 0x3f));
		/* Reject overlong encodings: minimal value for 2-byte is 0x80 */
		if (cp < 0x80)
			return 1;
		*cp_out = cp;
		return 0;
	}

	if (bytes == 3 && s[1] && s[2]) {
		unsigned char b1 = s[1], b2 = s[2];
		if ((b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80)
			return 1;
		uint32_t cp = (uint32_t)(((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6)
			| (b2 & 0x3f));
		/* Reject overlongs (min 0x800) and surrogates (D800-dfff) */
		if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))
			return 1;
		*cp_out = cp;
		return 0;
	}

	if (bytes == 4 && s[1] && s[2] && s[3]) {
		unsigned char b1 = s[1], b2 = s[2], b3 = s[3];
		if ((b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80)
			return 1;
		uint32_t cp = (uint32_t)(((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12)
			| ((b2 & 0x3f) << 6) | (b3 & 0x3f));
		/* Reject overlongs (min 0x10000) and values > U+10FFFF */
		if (cp < 0x10000 || cp > 0x10ffff)
			return 1;
		*cp_out = cp;
		return 0;
	}

	/* Continuation or invalid leading byte */
	return 1;
}

static char *
build_utf8_codepoint(const char *buf)
{
	if (!IS_UTF8_LEAD_BYTE(*buf))
		return "";

	uint32_t cp = 0;
	if (utf8_decode((const unsigned char *)buf, &cp) != 0)
		return "";

	/* The largest valid Unicode code point is U+10FFFF, so 32 bytes is enough */
	static char str[32];
	snprintf(str, sizeof(str), " (U+%X)", cp);
	return str;
}

void
print_header(void)
{
	CLEAR_SCREEN;
	static char *sep = NULL, *top = NULL, *base;
	if (!sep){
		sep = g_options.ascii_draw ? SEP_A : SEP_U;
		top = g_options.ascii_draw ? HEADER_TOP_A : HEADER_TOP_U;
		base = g_options.ascii_draw ? HEADER_BASE_A : HEADER_BASE_U;
	}

	const char *header_color = g_options.colors.header;
	const char *reset_color = g_options.colors.reset;
	const char *table_color = g_options.colors.table;

	const char *bold = *g_options.colors.header ? "\x1b[1m" : "";
	printf(" %s%s%s %s  (%sC-c%s: quit, %sC-x%s: clear)\n"
		" %s%s\n"
		" %s%s %sHex%s  %s%s%s %sOct%s  %s%s%s %sDec%s %s%s%s   %sBin%s    "
		"%s%s%s %sSym%s  %s%s\n"
		" %s%s\n",
		bold, PROG_NAME, reset_color, VERSION,
		bold, reset_color, bold, reset_color,
		table_color, top,
		sep, reset_color, header_color, reset_color,
		table_color, sep, reset_color, header_color, reset_color,
		table_color, sep, reset_color, header_color, reset_color,
		table_color, sep, reset_color, header_color, reset_color,
		table_color, sep, reset_color, header_color, reset_color,
		table_color, sep, base, reset_color);
}

static int
retrieve_ticap(const char *seq, const int term_type)
{
	if (g_options.show_terminfo_cap == 0)
		return 0;

	if (term_type != TK_TERM_KITTY)
		return 1;

	const size_t len = strlen(seq);
	if (len > 0 && seq[len - 1] == 'u')
		return 0;

	return 1;
}

void
print_footer(char *buf, const int is_utf8, const int clear_screen)
{
	static int edge = TABLE_WIDTH + 5;

	const int term_type = get_term_type();
	const int ret_ticap = retrieve_ticap(buf, term_type);
	char *str = translate_key(buf, term_type);
	const char *ticap = (str && ret_ticap == 1)	? build_ticap(str) : "";

	const int wlen = (str && is_utf8 == 1) ? (int)wc_xstrlen(str) : 0;
	int overlong = 0;
	if (wlen == 0 && str && strlen(str) > TABLE_WIDTH) /* flawfinder: ignore */
		overlong = 1;

	const char *color = is_utf8 == 1 ? "" : g_options.colors.translation;
	const char *utf8_cp = is_utf8 == 1 ? build_utf8_codepoint(buf) : "";
	const int ascii = g_options.ascii_draw;
	const char *table_color = g_options.colors.table;
	const char *reset_color = g_options.colors.reset;
	const char *sep = ascii ? SEP_A : SEP_U;

	printf(" %s%s\n"
		" %s%s %s%s%s%s\x1b[%dG%s%s%s\n",
		table_color, ascii ? FOOTER_TOP_A : FOOTER_TOP_U,
		sep, reset_color,
		color, str ? str : "?",
		*utf8_cp ? utf8_cp : ticap, reset_color, edge,
		table_color, overlong == 0 ? sep : "", reset_color);

	if (clear_screen == 0)
		printf(" %s%s%s\n", table_color,
			ascii ? FOOTER_BASE_NO_CLR_A : FOOTER_BASE_NO_CLR_U, reset_color);
	else
		printf(" %s%s%s\n", table_color,
			ascii ? FOOTER_BASE_CLR_A : FOOTER_BASE_CLR_U, reset_color);

	memset(buf, '\0', BUF_SIZE);
	free(str);
}

void
print_row(const int c, const char *s)
{
	static char *sep = NULL;
	if (!sep)
		sep = g_options.ascii_draw ? SEP_A : SEP_U;
	const char *code_color = g_options.colors.code;
	const char *reset_color = g_options.colors.reset;
	const char *table_color = g_options.colors.table;

	printf(" %s%s%s %s\\x%02x%s %s%s%s %s\\%03o%s %s%s%s %s%3d%s %s%s%s "
		"%s%s%s %s%s%s %s%*s%s %s%s%s\n",
		table_color, sep, reset_color, code_color, c, reset_color,
		table_color, sep, reset_color, code_color, c, reset_color,
		table_color, sep, reset_color, code_color, c, reset_color,
		table_color, sep, reset_color, code_color, build_binary((uint8_t)c),
		reset_color,
		table_color, sep, reset_color,
		g_options.colors.symbol, 4, s, reset_color, table_color, sep,
		reset_color);
}

void
print_bottom_line(const int clear_screen)
{
	const int ascii = g_options.ascii_draw;
	const char *table_color = g_options.colors.table;
	const char *reset_color = g_options.colors.reset;

	if (clear_screen == 0)
		printf(" %s%s%s\n", table_color,
			ascii ? BOTTOM_NO_CLR_A : BOTTOM_NO_CLR_U, reset_color);
	else
		printf(" %s%s%s\n", table_color,
			ascii ? BOTTOM_CLR_A : BOTTOM_CLR_U, reset_color);
}
