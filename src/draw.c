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

#include "keypress.h" /* BUF_SIZE, PROG_NAME, VERSION */
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

void
print_header(void)
{
	CLEAR_SCREEN;

	const char *bold = *g_options.colors.header ? "\x1b[1m" : "";
	printf(" %s%s%s %s  (%sC-c%s: quit, %sC-x%s: clear)\n"
		" ┌──────┬──────┬─────┬──────────┬──────┐\n"
		" │ %sHex%s  │ %sOct%s  │ %sDec%s │   %sBin%s    │ %sSym%s  │\n"
		" ├──────┼──────┼─────┼──────────┼──────┤\n",
		bold, PROG_NAME, g_options.colors.reset, VERSION,
		bold, g_options.colors.reset, bold, g_options.colors.reset,
		g_options.colors.header, g_options.colors.reset,
		g_options.colors.header, g_options.colors.reset,
		g_options.colors.header, g_options.colors.reset,
		g_options.colors.header, g_options.colors.reset,
		g_options.colors.header, g_options.colors.reset);
}

void
print_footer(char *buf, const int is_utf8, const int clear_screen)
{
	static int edge = TABLE_WIDTH + 5;

	char *str = translate_key(buf);
	const int wlen = (str && is_utf8 == 1) ? (int)wc_xstrlen(str) : 0;
	if (wlen == 0 && str && strlen(str) > TABLE_WIDTH - 1)
		str[TABLE_WIDTH] = '\0';

	printf(" ├──────┴──────┴─────┴──────────┴──────┤\n"
		" │ %s%s%s\x1b[%dG│\n", g_options.colors.translation, str ? str : "?",
		g_options.colors.reset, edge);

	if (clear_screen == 0)
		printf(" ├─────────────────────────────────────┤\n");
	else
		printf(" └─────────────────────────────────────┘\n");

	memset(buf, '\0', BUF_SIZE);
	free(str);
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

void
print_row(const int c, const char *s)
{
	printf(" │ %s\\x%02x%s │ %s\\%03o%s │ %s%3d%s │ %s%s%s │ %s%*s%s │\n",
		g_options.colors.code, c, g_options.colors.reset,
		g_options.colors.code, c, g_options.colors.reset,
		g_options.colors.code, c, g_options.colors.reset,
		g_options.colors.code, build_binary((uint8_t)c), g_options.colors.reset,
		g_options.colors.symbol, 4, s, g_options.colors.reset);
}

void
print_bottom_line(const int clear_screen)
{
	if (clear_screen == 0)
		printf(" ├──────┼──────┼─────┼──────────┼──────┤\n");
	else
		printf(" └──────┴──────┴─────┴──────────┴──────┘\n");
}
