/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025-2026 L. Abramovich <leo.clifm@outlook.com>
*/

/* config.h */

/* Default value for options */
#define DEFAULT_APP_CURSOR_KEYS 0
#define DEFAULT_ASCII_DRAW   0
#define DEFAULT_CLEAR_SCREEN 1
#define DEFAULT_COLOR        1
#define DEFAULT_HP_KEYS      0
#define DEFAULT_KITTY_KEYS   0 /* 1: disambiguate, 2: full. */
#define DEFAULT_LIGHT_THEME  0
#define DEFAULT_SCO_KEYS     0
#define DEFAULT_SHOW_TERMINFO_CAP 1
#define DEFAULT_SHOW_TRANSLATION 1
#define DEFAULT_TRANSLATE    NULL
#define DEFAULT_XTERM_CSI_U  0
#define DEFAULT_XTERM_MOK    0 /* 1: disambiguate, 2: full. */

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
