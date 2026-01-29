/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025-2026 L. Abramovich <leo.clifm@outlook.com>
*/

/* terminfo_caps.h */

#ifndef TERMINFO_CAPS_H
#define TERMINFO_CAPS_H

#ifdef __cplusplus
extern "C" {
#endif

const char *build_terminfo_cap(const char *str, const int is_canonical_seq,
	const int is_rxvt);

#ifdef __cplusplus
}
#endif

#endif /* TERMINFO_CAPS_H */
