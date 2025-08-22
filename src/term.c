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
#include <unistd.h>  /* STDIN_FILENO */

#include "term.h"    /* macros */
#include "options.h" /* g_options */

struct termios orig_termios;

static void
switch_to_alternate_buffer(void)
{
	SET_ALT_SCREEN;
	HIDE_CURSOR;
	if (g_options.kitty_keys > 0)
		SET_KITTY_KEYS((g_options.kitty_keys > 1));
}

static void
switch_to_normal_buffer(void)
{
	if (g_options.kitty_keys > 0)
		UNSET_KITTY_KEYS((g_options.kitty_keys > 1));
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
	raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | ISIG);
	raw.c_iflag &= (tcflag_t)~(IXON | IXOFF | ICRNL | INPCK);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
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
	switch_to_alternate_buffer();
	enable_raw_mode();
}
