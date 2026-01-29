/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025-2026 L. Abramovich <leo.clifm@outlook.com>
*/

/* options.h */

#ifndef OPTIONS_H
#define OPTIONS_H

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct color_t {
	char *code;
	char *header;
	char *reset;
	char *symbol;
	char *table;
	char *translation;
};

struct opts_t {
	struct color_t colors;
	char *translate;
	int app_cursor_keys;
	int ascii_draw;
	int clear_screen;
	int color;
	int hp_keys;
	int kitty_keys;
	int light_theme;
	int sco_keys;
	int show_terminfo_cap;
	int show_translation;
	int xterm_csi_u;
	int xterm_mok;
};
extern struct opts_t g_options;

void parse_cmdline_args(const int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* OPTIONS_H */
