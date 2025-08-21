/* keypress.h */

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

#ifndef KEYPRESS_H
#define KEYPRESS_H

#define PROG_NAME "keypress"
#define VERSION   "0.3.3"

#define CLEAR_SCREEN fputs("\x1b[H\x1b[2J\x1b[3J", stdout)

/* Ctrl+C */
#define KITTY_EXIT_KEY(s, c) (*(s) == ESC_KEY && \
	(c) == 'u' && strcmp((s) + 1, "[99;5") == 0)
/* Ctrl+X */
#define KITTY_CLR_KEY(s, c) (*(s) == ESC_KEY && \
	(c) == 'u' && strcmp((s) + 1, "[120;5") == 0)

#define EXIT_KEY  0x03 /* Ctrl+C */
#define CLR_KEY   0x18 /* Ctrl+X */
#define ESC_KEY   0x1b /* Esc */
#define DEL_KEY   0x7f /* Del */
#define NBSP_KEY  0xa0 /* NBSP */
#define SHY_KEY   0xad /* SHY */
#define SPACE_KEY 0x20 /* Space */

#define TABLE_WIDTH 35
#define IS_CTRL_KEY(c)    ((c) >= 0 && (c) <= 31)
#define IS_OCTAL_DIGIT(c) ((c) >= '0' && (c) <= '7')

#define IS_UTF8_LEAD_BYTE(c) (((c) & 0xc0) == 0xc0)
#define IS_UTF8_CONT_BYTE(c) (((c) & 0xc0) == 0x80)
#define IS_UTF8_CHAR(c)      (IS_UTF8_LEAD_BYTE((c)) || IS_UTF8_CONT_BYTE((c)))

/* 32 bytes to hold bytes of an escape sequence or a UTF-8 character */
#define BUF_SIZE 32

extern int g_kitty_keys;

#endif /* KEYPRESS_H */
