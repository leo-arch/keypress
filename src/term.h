/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025-2026 L. Abramovich <leo.clifm@outlook.com>
*/

/* term.h */

#ifndef TERM_H
#define TERM_H

#include <stdio.h> /* fputs */

#ifdef __cplusplus
extern "C" {
#endif

#define CLEAR_SCREEN          fputs("\x1b[H\x1b[2J", stdout)
#define SET_KITTY_KEYS(n)     fprintf(stdout, "\x1b[>%du", (n) == 1 ? 8 : 1)
#define UNSET_KITTY_KEYS      fputs("\x1b[<u", stdout)
#define HIDE_CURSOR           fputs("\x1b[?25l", stdout)
#define UNHIDE_CURSOR         fputs("\x1b[?25h", stdout)
#define SET_ALT_SCREEN        fputs("\x1b[?1049h", stdout)
#define UNSET_ALT_SCREEN      fputs("\x1b[?1049l", stdout)
#define SET_APP_CURSOR_KEYS   fputs("\x1b[?1h", stdout)
#define UNSET_APP_CURSOR_KEYS fputs("\x1b[?1l", stdout)

/* XTerm-specific resources to handle escape sequences */
/* See https://invisible-island.net/xterm/ctlseqs/ctlseqs.html for the escape
 * sequence as such, and https://invisible-island.net/xterm/manpage/xterm.html#VT100-Widget-Resources:modifyOtherKeys
 * for available parameters (0-3): 3 = Full, 2 = disambiguate. */
#define SET_XTERM_MOK(n)      fprintf(stdout, "\x1b[>4;%dm", (n) == 1 ? 3 : 2)
#define UNSET_XTERM_MOK       fputs("\x1b[>4;0m", stdout)

#define SET_XTERM_MOD_CUR_KEYS       fputs("\x1b[>1;4m", stdout)
#define SET_XTERM_MOD_FUNC_KEYS      fputs("\x1b[>2;4m", stdout)
#define SET_XTERM_MOD_KP_KEYS        fputs("\x1b[>3;4m", stdout)
#define SET_XTERM_MOD_SPECIAL_KEYS   fputs("\x1b[>7;4m", stdout)
#define UNSET_XTERM_MOD_CUR_KEYS     fputs("\x1b[>1;2m", stdout)
#define UNSET_XTERM_MOD_FUNC_KEYS    fputs("\x1b[>2;2m", stdout)
#define UNSET_XTERM_MOD_KP_KEYS      fputs("\x1b[>3;2m", stdout)
#define UNSET_XTERM_MOD_SPECIAL_KEYS fputs("\x1b[>7;0m", stdout)

#define XTERM_CSI_U_CUR_KEYS(n)     fprintf(stdout, "\x1b[>1;%df", (n))
#define XTERM_CSI_U_FUNC_KEYS(n)    fprintf(stdout, "\x1b[>2;%df", (n))
#define XTERM_CSI_U_KP_KEYS(n)      fprintf(stdout, "\x1b[>3;%df", (n))
#define XTERM_CSI_U_OTHER_KEYS(n)   fprintf(stdout, "\x1b[>4;%df", (n))
#define XTERM_CSI_U_SPECIAL_KEYS(n) fprintf(stdout, "\x1b[>7;%df", (n))

int  get_term_type(char **term_str);
void init_term(void);
void deinit_term(void);

#ifdef __cplusplus
}
#endif

#endif /* TERM_H */
