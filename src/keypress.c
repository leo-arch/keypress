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

#include <stdlib.h> /* EXIT_SUCCCESS, EXIT_FAILURE, malloc, free, strtol */
#include <unistd.h> /* read */
#include <string.h> /* strcmp, strlen, memset */
#include <ctype.h>  /* isprint */
#include <errno.h>  /* ENOMEM */
#include <limits.h> /* CHAR_MIN, CHAR_MAX */

#include "draw.h" /* print_header, print_row, print_footer, print_bottom_line */
#include "keypress.h" /* macros */
#include "options.h" /* parse_cmdline_args */
#include "translate_key.h" /* translate_key, is_end_seq_char */
#include "term.h" /* init_term, deinit_term */

/* Symbols for control characters */
const char *const keysym_table[] = {
	"NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL",
	"BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI", "DLE",
	"DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB", "CAN",
	"EM", "SUB", "ESC", "FS", "GS", "RS", "US", "SP", NULL
};

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
			*out_ptr++ = (char)n;
			ptr += 4;
		} else {
			*out_ptr++ = *ptr++;
		}
	}

	*out_ptr = '\0';
}

int
get_term_type(void)
{
	if (g_options.sco_keys == 1)
		return TK_TERM_LEGACY_SCO;
	if (g_options.hp_keys == 1)
		return TK_TERM_LEGACY_HP;
	if (g_options.kitty_keys > 0)
		return TK_TERM_KITTY;
	return TK_TERM_GENERIC;
}

static int
run_translate_key(const char *arg)
{
	if (!arg) {
		fprintf(stderr, "Missing parameter: An escape sequence is expected\n");
		fprintf(stderr, "E.g.: %s -t \"\\x1b[1;11D\"\n", PROG_NAME);
		return EXIT_FAILURE;
	}

	char *str = malloc((strlen(arg) + 1) * sizeof(char)); /* flawfinder: ignore */
	if (!str)
		return ENOMEM;

	transform_esc_seq(arg, str);

	char *key_sym = translate_key(str, get_term_type());
	free(str);

	if (key_sym) {
		printf("%s\n", key_sym);
		free(key_sym);
		return EXIT_SUCCESS;
	}

	fprintf(stderr, "%s: '%s': Unknown escape sequence\n", PROG_NAME, arg);
	return EXIT_FAILURE;
}

static const char *
get_ctrl_keysym(const int c, const int utf8)
{
	switch (c) {
	case DEL_KEY:   return "DEL";
	case NBSP_KEY:  return "NBSP";
	case SHY_KEY:   return "SHY";
	case SPACE_KEY: return "SP";
	case ALT_CSI:   return (utf8 ? "" : "CSI");
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

	if (buf[0] != ESC_KEY && (unsigned char)buf[0] != ALT_CSI)
		return 0; /* Not an escape sequence */

#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
	if (g_options.sco_keys == 1 && buf[0] == ESC_KEY
	&& buf[1] == CSI_INTRODUCER && !IS_DIGIT(c) && c != ';') /* VT100/SCO sequence */
		return 1;

	if (is_end_seq_char((const unsigned char)c)) /* CSI or SS3 sequence */
		return 1;

	if (!buf[1] && c != CSI_INTRODUCER && c != SS3_INTRODUCER) /* Alt */
		return 1;

	return 0;
}

#define CTRL_KEY_EXIT 1
#define CTRL_KEY_CONT 2

struct state_t {
	char buf[BUF_SIZE];
	char *buf_ptr;
	int utf8_bytes;
	int utf8_count;
	int clear_screen;
	int exit;
};

static void
handle_ctrl_keys(struct state_t *state, const int c)
{
	state->exit = 0;

	/* Ctrl+C */
	if (c == EXIT_KEY || KITTY_EXIT_KEY(state->buf, c)
	|| XTERM_MOK_EXIT_KEY(state->buf, c)) {
		state->exit = CTRL_KEY_EXIT;
		return;
	}

	/* Ctrl+X (kitty and Xterm with modifyOtherKeys) */
	if (KITTY_CLR_KEY(state->buf, c)
	|| XTERM_MOK_CLR_KEY(state->buf, c)) {
		state->clear_screen = 0;
		print_header();
		memset(state->buf, 0, BUF_SIZE);
		state->buf_ptr = state->buf;
		state->exit = CTRL_KEY_CONT;
		return;
	}

	if (c == CLR_KEY || state->clear_screen == 1) { /* Ctrl+X */
		state->clear_screen = 0;
		print_header();

		if (c == CLR_KEY) /* Ctrl+X: do not print info about this key. */
			state->exit = CTRL_KEY_CONT;
	}
}

static void
update_utf8_info(struct state_t *state, const int c)
{
	*state->buf_ptr++ = (char)c;
	state->utf8_count++;
	const int bytes = IS_UTF8_LEAD_BYTE(c)
		? utf8_char_bytes((unsigned char)c) : 0;
	if (bytes > 1)
		state->utf8_bytes = bytes;
}

static void
print_byte_info(struct state_t *state, const int c)
{
	if (IS_CTRL_KEY(c)) { /* Control characters */
		print_row(c, keysym_table[c]);
		return;
	}

	if (isprint(c) && c != SPACE_KEY) { /* ASCII printable characters */
		const char s[2] = {(char)c, 0};
		print_row(c, s);
		return;
	}

	/* Extended ASCII, Unicode */
	if (IS_UTF8_CHAR(c))
		update_utf8_info(state, c);

	print_row(c, get_ctrl_keysym(c, state->utf8_bytes));
}

static void
print_sequence(struct state_t *state, const int is_utf8, const int c)
{
	if (is_utf8 == 0)
		*state->buf_ptr++ = (char)c;
	else
		state->utf8_count = state->utf8_bytes = 0;

	state->clear_screen = g_options.clear_screen == 1;
	*state->buf_ptr = '\0';

	if (g_options.show_translation == 0) {
		print_bottom_line(state->clear_screen);
		memset(state->buf, '\0', BUF_SIZE);
	} else {
		print_footer(state->buf, is_utf8, g_options.clear_screen);
	}

	state->buf_ptr = state->buf;
}

static void
update_buffer(struct state_t *state, const int c)
{
	/* Avoid writing past the end of the buffer. */
	if (state->buf_ptr >= state->buf + (BUF_SIZE - 1))
		state->buf_ptr = state->buf;

	if (c == ESC_KEY || (c == ALT_CSI && state->utf8_bytes == 0)) {
		*state->buf_ptr++ = (char)c;
		return;
	}

	if (is_complete_escape_sequence(state->buf, c)) {
		/* Key combination involving modifier keys (Ctrl, Alt, Super). */
		print_sequence(state, 0, c);
		return;
	}

	if (state->utf8_bytes > 1 && state->utf8_count == state->utf8_bytes) {
		/* A UTF-8 character. */
		print_sequence(state, 1, 0);
		return;
	}

	if ((state->buf[0] == ESC_KEY || (unsigned char)state->buf[0] == ALT_CSI)
	&& state->utf8_bytes == 0) {
		/* Append byte to the buffer only provided we are in the
		 * middle of an escape sequence. */
		*state->buf_ptr++ = (char)c;
		return;
	}

	if (!IS_UTF8_CHAR(c)) {
		/* Print a bottom line (for ASCII characters only). */
		state->clear_screen = g_options.clear_screen == 1;
		print_bottom_line(state->clear_screen);
	}
}

int
main(int argc, char **argv)
{
	parse_cmdline_args(argc, argv);

	if (g_options.translate != NULL) /* -t SEQ */
		return run_translate_key(g_options.translate);

	init_term();

	struct state_t state = {0};
	state.buf_ptr = state.buf;

	print_header();
	fflush(stdout);

	unsigned char ch = 0;
	while (1) {
		const ssize_t bytes_read = read(STDIN_FILENO, &ch, sizeof(ch)); /* flawfinder: ignore */
		if (bytes_read == -1) {
			perror("Error reading input");
			break;
		} else if (bytes_read == 0) {
			break; /* EOF reached */
		}

		const int c = (int)ch;

		handle_ctrl_keys(&state, c);
		if (state.exit == CTRL_KEY_CONT) {
			fflush(stdout);
			continue;
		}
		if (state.exit == CTRL_KEY_EXIT)
			break;

		print_byte_info(&state, c);
		update_buffer(&state, c);

		fflush(stdout);
	}

	fflush(stdout);
	deinit_term();
	return EXIT_SUCCESS;
}
