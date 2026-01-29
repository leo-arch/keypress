/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025-2026 L. Abramovich <leo.clifm@outlook.com>
*/

/* keypress.h */

#ifndef KEYPRESS_H
#define KEYPRESS_H

#ifdef __cplusplus
extern "C" {
#endif

#define PROG_NAME "keypress"
#define VERSION   "0.3.6"

#define EXIT_KEY  0x03 /* Ctrl+C */
#define CLR_KEY   0x18 /* Ctrl+X */
#define ESC_KEY   0x1b /* Esc */
#define DEL_KEY   0x7f /* Del */
#define NBSP_KEY  0xa0 /* NBSP */
#define SHY_KEY   0xad /* SHY */
#define SPACE_KEY 0x20 /* Space */

#define IS_CTRL_KEY(c)    ((c) >= 0 && (c) <= 31)
#define IS_OCTAL_DIGIT(c) ((c) >= '0' && (c) <= '7')
#define IS_DIGIT(c)       ((c) >= '0' && (c) <= '9')

#define IS_UTF8_LEAD_BYTE(c) (((c) & 0xc0) == 0xc0)
#define IS_UTF8_CONT_BYTE(c) (((c) & 0xc0) == 0x80)
#define IS_UTF8_CHAR(c)      (IS_UTF8_LEAD_BYTE((c)) || IS_UTF8_CONT_BYTE((c)))

/* 32 bytes to hold bytes of an escape sequence or a UTF-8 character */
#define BUF_SIZE 32

/* Ctrl+c */
#define XTERM_MOK_EXIT_KEY(seq, end_char) (*(seq) == ESC_KEY && \
	(end_char) == '~' && strcmp((seq) + 1, "[27;5;99") == 0)
/* Ctrl+x */
#define XTERM_MOK_CLR_KEY(seq, end_char) (*(seq) == ESC_KEY && \
	(end_char) == '~' && strcmp((seq) + 1, "[27;5;120") == 0)

/* Ctrl+c */
#define KITTY_EXIT_KEY(seq, end_char) (*(seq) == ESC_KEY && \
	(end_char) == 'u' && strcmp((seq) + 1, "[99;5") == 0)
/* Ctrl+x */
#define KITTY_CLR_KEY(seq, end_char) (*(seq) == ESC_KEY && \
	(end_char) == 'u' && strcmp((seq) + 1, "[120;5") == 0)

#ifdef __cplusplus
}
#endif

#endif /* KEYPRESS_H */
