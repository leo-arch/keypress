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

/* Lenght of the table, excluding borders. */
#define TABLE_WIDTH 35

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
	uint32_t cp = 0;
	if (utf8_decode((const unsigned char *)buf, &cp) != 0)
		return "";

	/* The largest valid Unicode code point is U+10FFFF, so 32 bytes is enough */
	static char str[32];
	snprintf(str, sizeof(str), " (U+%X)", cp);
	return str;
}

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

void
print_footer(char *buf, const int is_utf8, const int clear_screen)
{
	static int edge = TABLE_WIDTH + 5;

	char *str = translate_key(buf, get_term_type());

	const int wlen = (str && is_utf8 == 1) ? (int)wc_xstrlen(str) : 0;
	int overlong = 0;
	if (wlen == 0 && str && strlen(str) > TABLE_WIDTH)
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
		utf8_cp, reset_color, edge,
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
