/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025-2026 L. Abramovich <leo.clifm@outlook.com>
*/

/* draw.h */

#ifndef DRAW_H
#define DRAW_H

#ifdef __cplusplus
extern "C" {
#endif

int  utf8_char_bytes(unsigned char c);
void print_header(const char *term_name);
void print_footer(char *buf, const int is_utf8, const int clear_screen,
	const int term_type);
void print_row(const int c, const char *s);
void print_bottom_line(const int clear_screen);

#ifdef __cplusplus
}
#endif

#endif /* DRAW_H */
