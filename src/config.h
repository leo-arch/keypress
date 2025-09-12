/* config.h */

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

/* Default value for options */
#define DEFAULT_ASCII_DRAW   0
#define DEFAULT_CLEAR_SCREEN 1
#define DEFAULT_COLOR        1
#define DEFAULT_HP_KEYS      0
#define DEFAULT_KITTY_KEYS   0 /* 1: enable, 2: full. */
#define DEFAULT_LIGHT_THEME  0
#define DEFAULT_SCO_KEYS     0
#define DEFAULT_SHOW_TERMINFO_CAP 1
#define DEFAULT_SHOW_TRANSLATION 1
#define DEFAULT_TRANSLATE    NULL
#define DEFAULT_XTERM_MOK    0

/* Default colors */
/* Dark background */
#define CODE_COLOR   "\x1b[36m"  /* Code (hex, oct, dec): cyan */
#define HEADER_COLOR "\x1b[32m"  /* Header: green */
#define SYM_COLOR    "\x1b[33m"  /* Symbol: yellow */
#define TABLE_COLOR  "\x1b[2m"   /* Table: dim */
#define TRANS_COLOR  "\x1b[1m"   /* Translation: bold */

/* Light background (-l) */
#define CODE_COLOR_LIGHT   "\x1b[2;35m"   /* Code (hex, oct, dec): dimmed magenta */
#define HEADER_COLOR_LIGHT "\x1b[34m"  /* Header: blue */
#define SYM_COLOR_LIGHT    "\x1b[31m"  /* Symbol: red */
#define TABLE_COLOR_LIGHT  "\x1b[2m"   /* Table: dim */
#define TRANS_COLOR_LIGHT  "\x1b[1m"   /* Translation: bold */

#define RESET "\x1b[0m"   /* Reset attributes */
