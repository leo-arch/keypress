/* keypress.c */

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* read */
#include <string.h>
#include <ctype.h>  /* isprint */
#include <errno.h>  /* ENOMEM */
#include <limits.h> /* CHAR_MIN, CHAR_MAX */

#include "draw.h"
#include "keypress.h" /* macros */
#include "options.h" /* parse_cmdline_args */
#include "translate_key.h" /* translate_key, is_end_seq_char */
#include "term.h" /* init_term, deinit_term */

/* Symbols for control characters */
const char *const keysym[] = {
	"NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL",
	"BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI", "DLE",
	"DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB", "CAN",
	"EM", "SUB", "ESC", "FS", "GS", "RS", "US", "SP", NULL
};

static int
utf8_char_bytes(unsigned char c)
{
    c >>= 4;
    c &= 7;

	return (c == 4) ? 2 : c - 3;
}

/* Transform escape strings ("\\e", hex, and octal) in the string INPUT
 * into the corresponding integer byte. The converted string is copied
 * into the OUTPUT buffer. */
static void
transform_esc_seq(const char *input, char *output)
{
	const char *ptr = input;
	char *out_ptr = output;

	while (*ptr) {
		if (*ptr != '\\') {
			/* Not an escape string: copy the character as is. */
			*out_ptr++ = *ptr++;
		} else if (ptr[1] == 'e') { /* "\\e" */
			*out_ptr++ = ESC_KEY;
			ptr += 2;
		} else if (ptr[1] == 'x'     /* Hex */
		|| IS_OCTAL_DIGIT(ptr[1])) { /* Octal */
			const int hex = ptr[1] == 'x';
			const long n = strtol(ptr + (hex ? 2 : 1), NULL, hex ? 16 : 8);
			if (n < CHAR_MIN || n > CHAR_MAX) {
				ptr++;
			} else {
				*out_ptr++ = (char)n;
				ptr += 4;
			}
		} else {
			*out_ptr++ = *ptr++;
		}
	}

	*out_ptr = '\0';
}

static int
run_translate_key(const char *arg)
{
	if (!arg) {
		fprintf(stderr, "Missing parameter: An escape sequence is expected\n");
		fprintf(stderr, "E.g.: %s -t \"\\x1b[1;11D\"\n", PROG_NAME);
		return EXIT_FAILURE;
	}

#ifdef TK_TEST
	if (strcmp(arg, "test") == 0)
		return key_test();
#endif

	char *str = malloc((strlen(arg) + 1) * sizeof(char));
	if (!str)
		return ENOMEM;

	transform_esc_seq(arg, str);

	char *key_sym = translate_key(str);
	free(str);

	if (key_sym) {
		printf("%s\n", key_sym);
		free(key_sym);
		return EXIT_SUCCESS;
	}

	fprintf(stderr, "%s: '%s': Unknown escape sequence\n", PROG_NAME, arg);
	return EXIT_FAILURE;
}

static char *
get_ctrl_keysym(const int c)
{
	switch (c) {
	case DEL_KEY:   return "DEL";
	case NBSP_KEY:  return "NBSP";
	case SHY_KEY:   return "SHY";
	case SPACE_KEY: return "SP";
	default:        return "";
	}
}

static int
is_complete_escape_sequence(const char *buf, const int c)
{
	if (c == 0) /* NULL */
		return 0;

	if (IS_CTRL_KEY(c))
		return 1;

	if (buf[0] != ESC_KEY) /* Not an escape sequence */
		return 0;

	if (is_end_seq_char((const unsigned char )c))
		return 1;

	if (!buf[1] && c != '[' && c != 'O') /* Alt */
		return 1;

	return 0;
}

int
main(int argc, char **argv)
{
	parse_cmdline_args(argc, argv);

	if (g_options.translate != NULL) /* -t SEQ */
		return run_translate_key(g_options.translate);

	init_term();

	char buf[BUF_SIZE] = "";
	char *ptr = buf;
	int clr_scr = 0;

	int utf8_bytes = 0; /* Number of bytes of a UTF-8 character. */
	int utf8_count = 0; /* Number of printed bytes of a UTF-8 character. */
	const int opts_clear_screen = g_options.clear_screen;

	print_header();

	unsigned char ch = 0;
	while (read(STDIN_FILENO, &ch, sizeof(ch)) == sizeof(ch)) {
		const int c = (int)ch;

		if (c == EXIT_KEY || KITTY_EXIT_KEY(buf, c)) /* Ctrl+C */
			break;

		if (KITTY_CLR_KEY(buf, c)) { /* Ctrl+X (kitty protocol) */
			clr_scr = 0; print_header();
			memset(buf, 0, sizeof(buf)); ptr = buf;
			continue;
		} else if (c == CLR_KEY /* Ctrl+X */
		|| clr_scr == 1) {
			clr_scr = 0; print_header();
			if (c == CLR_KEY)
				continue; /* Ctrl+X: do not print info about this key.  */
		}

		if (IS_CTRL_KEY(c)) { /* Control characters */
			print_row(c, keysym[c]);
		} else if (isprint(c) && c != 0x20) { /* ASCII printable characters */
			char s[2] = {(char)c, 0};
			print_row(c, s);
		} else { /* Extended ASCII, Unicode */
			print_row(c, get_ctrl_keysym(c));

			if (IS_UTF8_CHAR(c)) {
				utf8_count++;
				*ptr++ = (char)c;
				int bytes = IS_UTF8_LEAD_BYTE(c)
					? utf8_char_bytes((unsigned char)c) : 0;
				if (bytes > 1)
					utf8_bytes = bytes;
			}
		}

		if (c == ESC_KEY) {
			*ptr++ = (char)c;
		} else if (is_complete_escape_sequence(buf, c)) {
			/* Key combination involving modifier keys (Ctrl, Alt, Meta). */
			*ptr++ = (char)c;
			*ptr = '\0';
			print_footer(buf, 0, opts_clear_screen);
			ptr = buf;
			clr_scr = g_options.clear_screen == 1;
		} else if (utf8_bytes > 1 && utf8_count == utf8_bytes) {
			/* A UTF-8 character. */
			utf8_count = utf8_bytes = 0;
			*ptr = '\0';
			print_footer(buf, 1, opts_clear_screen);
			ptr = buf;
			clr_scr = opts_clear_screen == 1;
		} else if (buf[0] == ESC_KEY) {
			/* Append byte to the buffer only provided we are in the
			 * middle of an escape sequence. */
			*ptr++ = (char)c;
		} else if (!IS_UTF8_CHAR(c)) {
			/* Print a bottom line (for ASCII characters only). */
			clr_scr = opts_clear_screen == 1;
			print_bottom_line(clr_scr);
		}
	}

	deinit_term();
	return EXIT_SUCCESS;
}
