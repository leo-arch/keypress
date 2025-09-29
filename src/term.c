/* term.c */

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

#include <locale.h>  /* setlocale */
#include <termios.h> /* tcgetattr, tcsetattr */
#include <stdlib.h>  /* getenv */
#include <string.h>  /* strstr */
#include <unistd.h>  /* STDIN_FILENO */

#include "term.h"    /* macros */
#include "translate_key.h" /* TK_TERM macros */
#include "options.h" /* g_options */

struct termios orig_termios;

static void
switch_to_alternate_buffer(void)
{
	SET_ALT_SCREEN;
	HIDE_CURSOR;

	if (g_options.kitty_keys > 0) {
		SET_KITTY_KEYS((g_options.kitty_keys > 1));
	} else if (g_options.xterm_mok > 0) {
		SET_XTERM_MOK(g_options.xterm_mok > 1);
		if (g_options.xterm_mok > 1) {
			SET_XTERM_MOD_CUR_KEYS;
			SET_XTERM_MOD_FUNC_KEYS;
			SET_XTERM_MOD_KP_KEYS;
			SET_XTERM_MOD_SPECIAL_KEYS;
		}
		if (g_options.xterm_csi_u == 1) {
			XTERM_CSI_U_CUR_KEYS(1);
			XTERM_CSI_U_FUNC_KEYS(1);
			XTERM_CSI_U_KP_KEYS(1);
			XTERM_CSI_U_OTHER_KEYS(1);
			XTERM_CSI_U_SPECIAL_KEYS(1);
		}
	}

	if (g_options.app_cursor_keys == 1)
		SET_APP_CURSOR_KEYS;
}

static void
switch_to_normal_buffer(void)
{
	if (g_options.kitty_keys > 0) {
		UNSET_KITTY_KEYS;
	} else if (g_options.xterm_mok > 0) {
		UNSET_XTERM_MOK;
		if (g_options.xterm_mok > 1) {
			UNSET_XTERM_MOD_CUR_KEYS;
			UNSET_XTERM_MOD_FUNC_KEYS;
			UNSET_XTERM_MOD_KP_KEYS;
			UNSET_XTERM_MOD_SPECIAL_KEYS;
		}
		if (g_options.xterm_csi_u == 1) {
			XTERM_CSI_U_CUR_KEYS(0);
			XTERM_CSI_U_FUNC_KEYS(0);
			XTERM_CSI_U_KP_KEYS(0);
			XTERM_CSI_U_OTHER_KEYS(0);
			XTERM_CSI_U_SPECIAL_KEYS(0);
		}
	}

	if (g_options.app_cursor_keys == 1)
		UNSET_APP_CURSOR_KEYS;

	UNHIDE_CURSOR;
	UNSET_ALT_SCREEN;
}

static void
disable_raw_mode(void)
{
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

static void
enable_raw_mode(void)
{
	tcgetattr(STDIN_FILENO, &orig_termios);
	struct termios raw = orig_termios;
	raw.c_iflag &= (tcflag_t)~(ICRNL | ISTRIP | IXON | IXOFF | INLCR);
	raw.c_iflag &= (tcflag_t)~(INPCK | PARMRK | IGNPAR | IGNBRK | BRKINT);
	raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | ISIG | IEXTEN);
	raw.c_cflag &= (tcflag_t)~(PARENB | PARODD);
	raw.c_cflag |= CS8;
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &raw);

	setvbuf(stdout, NULL, _IOFBF, BUFSIZ);
}

void
deinit_term(void)
{
	switch_to_normal_buffer();
    disable_raw_mode();
}

void
init_term(void)
{
	setlocale(LC_ALL, "");
	enable_raw_mode();
	switch_to_alternate_buffer();
}

static void
set_xterm_terminal(char **term)
{
	if (getenv("XTERM_VERSION"))
		return; /* Actual XTerm */

	const char *vte = getenv("VTE_VERSION");
	char *name = NULL;

	if (getenv("KONSOLE_VERSION")) name = "konsole";
	else if (getenv("GNOME_TERMINAL_SCREEN")) name = "gnome";
	else if (getenv("WEZTERM_EXECUTABLE")) name = "wezterm";
	else if (getenv("TERMINOLOGY")) name = "terminology";
	else if (getenv("TERMINATOR_UUID")) name = "terminator";
	else if (getenv("ROXTERM_ID")) name = "roxterm";
	else if (getenv("TILIX_ID")) name = "tilix";
	else if (getenv("ALACRITTY_WINDOW_ID")) name = "alacritty"; /* cosmic-term */
	else if (getenv("MLTERM")) name = "mlterm";
	else if (getenv("LC_EXTRATERM_COOKIE")) name = "extraterm";
	else if (getenv("TABBY_CONFIG_DIRECTORY")) name = "tabby";
	else if (getenv("WAVETERM_VERSION")) name = "waveterm";

	static char buf[64] = "xterm";
	if (vte || name) {
		snprintf(buf + 5, sizeof(buf) - 5, " (%s%s%s)", name ? name : "",
			(vte && name) ? "/" : "", vte ? "VTE" : "");
	}

	*term = buf;
}

static int
set_term_type(const int term_type)
{
	if (g_options.sco_keys == 1) return TK_TERM_LEGACY_SCO;
	if (g_options.hp_keys == 1) return TK_TERM_LEGACY_HP;
	if (g_options.kitty_keys > 0) return TK_TERM_KITTY;
	return term_type;
}

int
get_term_type(char **term_str)
{
	char *term_program = getenv("TERM_PROGRAM");
	char *term = getenv("TERM");
	*term_str = (term_program && *term_program) ? term_program :
		((term && *term) ? term : "Unknown");

	char *colorterm = getenv("COLORTERM");

	if (colorterm) {
		if (strstr(colorterm, "rxvt")) {
			if (!term || !strstr(term, "rxvt"))
				*term_str = "rxvt";
			return set_term_type(TK_TERM_RXVT);
		} else if (strstr(colorterm, "Eterm"))
			return set_term_type(TK_TERM_RXVT);
	}

	if (!term || !*term)
		return set_term_type(TK_TERM_GENERIC);

	if (strstr(term, "xterm")) {
		if (!term_program)
			set_xterm_terminal(term_str);
		return set_term_type(TK_TERM_XTERM);
	}

	if (strstr(term, "rxvt") || strstr(term, "Eterm")
	|| strstr(term, "dvtm"))
		return set_term_type(TK_TERM_RXVT);
	if (strstr(term, "linux") || strstr(term, "cygwin")
	|| strstr(term, "yaft") || strstr(term, "fbterm"))
		return set_term_type(TK_TERM_LINUX);
	if (strstr(term, "st-") || strstr(term, "stterm"))
		return set_term_type(TK_TERM_ST);

	return set_term_type(TK_TERM_GENERIC);
}
