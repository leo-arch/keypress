/* translate_key.c */

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h> /* toupper() */
#include <errno.h> /* ENOMEM */

/* The Meta key is usually mapped to the Super/logo key (Mod4), for example,
 * on Wayland. Mod1 is typically Alt, while Mod2 is NumLock, and Mod5 AltGr
 * (Right Alt). Mod3 is normally left unassigned. */
static const char *mod_table[256] = {
	[1] = "Shift", [2] = "Alt", [4] = "Ctrl", [8] = "Meta",
	[3] = "Alt+Shift", [5] = "Ctrl+Shift", [9] = "Meta+Shift",
	[6] = "Ctrl+Alt", [7] = "Ctrl+Alt+Shift", [12] = "Ctrl+Meta",
	[10] = "Alt+Meta", [14] = "Ctrl+Alt+Meta", [15] = "Ctrl+Alt+Shift+Meta" 
};

static const char *key_table[256] = {
	[1] = "Home", [2] = "Ins", [3] = "Del", [4] = "End",
	[5] = "PgUp", [6] = "PgDn", [7] = "Home", [8] = "End",
	[10] = "F0", [11] = "F1", [12] = "F2", [13] = "F3",
	[14] = "F4", [15] = "F5", [17] = "F6", [18] = "F7",
	[19] = "F8", [20] = "F9", [21] = "F10", [23]= "F11", [24] = "F12",

	/* In Rxvt, these integers are mapped to either a function key above
	 * F12, or to the shifted number - 10. E.g., 25 is both F13 and Shift+F3.
	 * See https://pod.tst.eu/http://cvs.schmorp.de/rxvt-unicode/doc/rxvt.7.pod#Escape_Sequences */
	[25] = "F13", [26] = "F14", [28] = "F15", [29]= "F16", [31] = "F17",
	[32] = "F18", [33] = "F19", [34] = "F20",

	['A'] = "Up", ['B'] = "Down", ['C'] = "Right", ['D'] = "Left",
	/* Rxvt */
	['a'] = "Up", ['b'] = "Down", ['c'] = "Right", ['d'] = "Left",
	/* Xterm */
	['F'] = "End", ['G'] = "?", ['H'] = "Home",
	['P'] = "F1", ['Q'] = "F2", ['R'] = "F3", ['S'] = "F4"
};

#define IS_ARROW_CHAR(c) (((c) >= 'A' && (c) <= 'D') \
	|| ((c) >= 'a' && (c) <= 'd'))

#define IS_FUNC_CHAR(c) (((c) >= 'F' && (c) <= 'H') \
	|| ((c) >= 'P' && (c) <= 'S'))

#define IS_RXVT_KEYPAD_CHAR(c) (((c) >= 'j' && (c) <= 'y') || (c) == 'M')
#define IS_RXVT_END_CHAR(c)    ((c) == '^' || (c) == '@' || (c) == '$')

/* Max output string length */
#define MAX_BUF 256

static void
set_func_key_char(char *str, const size_t end, int *keycode, int *mod_key)
{
	*keycode = str[end];
	char *s = strchr(str, ';');
	if (s) {
		str[end] = '\0';
		*mod_key += (s && s[1]) ? atoi(s + 1) - 1 : 0;
	}
}

static void
set_arrow_key(char *str, size_t end, int *keycode, int *mod_key)
{
	*keycode = str[end];
	if (*str == '\x1b') {
		*mod_key += 2;
		str++;
		end--;
	}
	char *s = strchr(str, ';');
	if (s) {
		str[end] = '\0';
		*mod_key += (s && s[1]) ? atoi(s + 1) - 1 : 0;
	} else if (str[end] >= 'a' && str[end] <= 'd') {
		if (*str == 'O')
			*mod_key += 4;
		else
			(*mod_key)++;
	} else if (str[end] >= 'A' && str[end] <= 'D') {
		str[end] = '\0';
		if (*str == 'O')
			str++;
		if (*str >= '0' && *str <= '9')
			*mod_key += atoi(str) - 1;
	}
}

static void
set_key_tilde(char *str, const size_t end, int *keycode, int *mod_key)
{
	str[end] = '\0';
	if (*str == '\x1b') { // rxvt
		*mod_key += 2; // Alt
		*keycode = atoi(str + 2);
	} else {
		char *s = strchr(str, ';');
		if (s) *s = '\0';
		*keycode = atoi(str);
		*mod_key += (s && s[1]) ? atoi(s + 1) - 1 : 0;
	}
}

static void
set_rxvt_end_seq(char *str, const size_t end, int *keycode, int *mod_key)
{
	if (str[end] == '$')
		*mod_key += 1;
	else
		*mod_key += 4 + (str[end] == '@');

	str[end] = '\0';

	if (*str == '\x1b') {
		*mod_key += 2;
		str += 2;
	}

	*keycode = atoi(str);
}

static char *
print_non_esc_seq(const char *str)
{
	char *buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (*str == 0x7f && !str[1])
		snprintf(buf, MAX_BUF, "%s", "Del");
	else if (*str < 0x20 && !str[1])
		snprintf(buf, MAX_BUF, "%s%c", "Ctrl+", *str + '@');
	else if (*str == 0x20 && !str[1])
		snprintf(buf, MAX_BUF, "%s", "Space");
	else
		snprintf(buf, MAX_BUF, "%s", str);

	return buf;
}

static char *
check_single_key(char *str, const int csi_seq)
{
	char *buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (!*str) {
		snprintf(buf, MAX_BUF, "%s", "Escape");
		return buf;
	}

	if (*str == 'Z' && !str[1]) {
		snprintf(buf, MAX_BUF, "%s", "Shift+Tab");
		return buf;
	}

	if (*str == 0x08 || *str == 0x7f) {
		snprintf(buf, MAX_BUF, "%s", "Alt+Backspace");
		return buf;
	}

	if (!str[1] && csi_seq == 0) {
		if (*str < 0x20)
			snprintf(buf, MAX_BUF, "%s%c", "Ctrl+Alt+", *str + '@');
		else
			snprintf(buf, MAX_BUF, "%s%c", "Alt+", toupper(*str));
		return buf;
	}

	free(buf);
	return NULL;
}

static char *
print_keypad_code(const char end)
{
	char *buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (end == 'M')
		snprintf(buf, MAX_BUF, "%s", "Ctrl+Shift+Enter");
	else
		snprintf(buf, MAX_BUF, "%s%c", "Ctrl+Shift+", end - '@');

	return buf;
}

/* Translate the escape sequence STR into the corresponding symbolic value.
 * E.g. "\x1b[1;7D" will return "Ctrl+Alt+Left". If no symbolic value is
 * found, NULL is returned.
 * The returned value, if not NULL, is dinamically allocated and must be
 * free'd by the caller. */
char *
translate_key(char *str)
{
	if (!str || !*str)
		return NULL;

	if (*str != '\x1b')
		return print_non_esc_seq(str);

	const int csi_seq = str[1] == '[';
	str += str[1] == '[' ? 2 : 1;

	char *buf = check_single_key(str, csi_seq);
	if (buf)
		return buf;

	size_t len = strlen(str);

	int keycode = -1;
	int mod_key = 1;

	size_t end = len > 0 ? len - 1 : len;

	if (IS_FUNC_CHAR(str[end]))
		set_func_key_char(str, end, &keycode, &mod_key);
	else if (IS_ARROW_CHAR(str[end]))
		set_arrow_key(str, end, &keycode, &mod_key);
	else if (IS_RXVT_END_CHAR(str[end]))
		set_rxvt_end_seq(str, end, &keycode, &mod_key);
	else if (str[end] == '~')
		set_key_tilde(str, end, &keycode, &mod_key);
	else if (IS_RXVT_KEYPAD_CHAR(str[end]) && csi_seq == 0 && *str == 'O')
		return print_keypad_code(str[end]);
	else
		return NULL;

	mod_key--;
	const char *k = (keycode >= 0 && keycode <= 255) ? key_table[keycode] : NULL;
	const char *m = (mod_key >= 0 && mod_key <= 255) ? mod_table[mod_key] : NULL;

	if (!k)
		return NULL;

	buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (m)
		snprintf(buf, MAX_BUF, "%s+%s", m, k);
	else
		snprintf(buf, MAX_BUF, "%s", k);

	return buf;
}

#ifdef TK_TEST
struct keys_t {
	char *key;
	const char *translation;
};

struct keys_t keys[] = {
	/* xterm */
	{"\x1b[A", "Up"}, {"\x1b[B", "Down"},
	{"\x1b[C", "Right"}, {"\x1b[D", "Left"},

	{"\x1b[1;2A", "Shift+Up"}, {"\x1b[1;2B", "Shift+Down"},
	{"\x1b[1;2C", "Shift+Right"}, {"\x1b[1;2D", "Shift+Left"},

	{"\x1b[1;3A", "Alt+Up"}, {"\x1b[1;3B", "Alt+Down"},
	{"\x1b[1;3C", "Alt+Right"}, {"\x1b[1;3D", "Alt+Left"},

	{"\x1b[1;5A", "Ctrl+Up"}, {"\x1b[1;5B", "Ctrl+Down"},
	{"\x1b[1;5C", "Ctrl+Right"}, {"\x1b[1;5D", "Ctrl+Left"},

	{"\x1b[1;6A", "Ctrl+Shift+Up"}, {"\x1b[1;6B", "Ctrl+Shift+Down"},
	{"\x1b[1;6C", "Ctrl+Shift+Right"}, {"\x1b[1;6D", "Ctrl+Shift+Left"},

	{"\x1b[1;7A", "Ctrl+Alt+Up"}, {"\x1b[1;7B", "Ctrl+Alt+Down"},
	{"\x1b[1;7C", "Ctrl+Alt+Right"}, {"\x1b[1;7D", "Ctrl+Alt+Left"},

	{"\x1b[1;8A", "Ctrl+Alt+Shift+Up"}, {"\x1b[1;8B", "Ctrl+Alt+Shift+Down"},
	{"\x1b[1;8C", "Ctrl+Alt+Shift+Right"}, {"\x1b[1;8D", "Ctrl+Alt+Shift+Left"},

	{"\x1bOP", "F1"}, {"\x1bOQ", "F2"}, {"\x1bOR", "F3"},
	{"\x1bOS", "F4"}, {"\x1b[15~", "F5"}, {"\x1b[17~", "F6"},
	{"\x1b[18~", "F7"}, {"\x1b[19~", "F8"}, {"\x1b[20~", "F9"},
	{"\x1b[21~", "F10"}, {"\x1b[23~", "F11"}, {"\x1b[24~", "F12"},

	{"\x1b[1;2P", "Shift+F1"}, {"\x1b[1;2Q", "Shift+F2"},
	{"\x1b[1;2R", "Shift+F3"}, {"\x1b[1;2S", "Shift+F4"},
	{"\x1b[15;2~", "Shift+F5"}, {"\x1b[17;2~", "Shift+F6"},
	{"\x1b[18;2~", "Shift+F7"}, {"\x1b[19;2~", "Shift+F8"},
	{"\x1b[20;2~", "Shift+F9"}, {"\x1b[21;2~", "Shift+F10"},
	{"\x1b[23;2~", "Shift+F11"}, {"\x1b[24;2~", "Shift+F12"},

	{"\x1b[1;3P", "Alt+F1"}, {"\x1b[1;3Q", "Alt+F2"},
	{"\x1b[1;3R", "Alt+F3"}, {"\x1b[1;3S", "Alt+F4"},
	{"\x1b[15;3~", "Alt+F5"}, {"\x1b[17;3~", "Alt+F6"},
	{"\x1b[18;3~", "Alt+F7"}, {"\x1b[19;3~", "Alt+F8"},
	{"\x1b[20;3~", "Alt+F9"}, {"\x1b[21;3~", "Alt+F10"},
	{"\x1b[23;3~", "Alt+F11"}, {"\x1b[24;3~", "Alt+F12"},

	{"\x1b[1;4P", "Alt+Shift+F1"}, {"\x1b[1;4Q", "Alt+Shift+F2"},
	{"\x1b[1;4R", "Alt+Shift+F3"}, {"\x1b[1;4S", "Alt+Shift+F4"},
	{"\x1b[15;4~", "Alt+Shift+F5"}, {"\x1b[17;4~", "Alt+Shift+F6"},
	{"\x1b[18;4~", "Alt+Shift+F7"}, {"\x1b[19;4~", "Alt+Shift+F8"},
	{"\x1b[20;4~", "Alt+Shift+F9"}, {"\x1b[21;4~", "Alt+Shift+F10"},
	{"\x1b[23;4~", "Alt+Shift+F11"}, {"\x1b[24;4~", "Alt+Shift+F12"},

	{"\x1b[1;5P", "Ctrl+F1"}, {"\x1b[1;5Q", "Ctrl+F2"},
	{"\x1b[1;5R", "Ctrl+F3"}, {"\x1b[1;5S", "Ctrl+F4"},
	{"\x1b[15;5~", "Ctrl+F5"}, {"\x1b[17;5~", "Ctrl+F6"},
	{"\x1b[18;5~", "Ctrl+F7"}, {"\x1b[19;5~", "Ctrl+F8"},
	{"\x1b[20;5~", "Ctrl+F9"}, {"\x1b[21;5~", "Ctrl+F10"},
	{"\x1b[23;5~", "Ctrl+F11"}, {"\x1b[24;5~", "Ctrl+F12"},

	{"\x1b[1;6P", "Ctrl+Shift+F1"}, {"\x1b[1;6Q", "Ctrl+Shift+F2"},
	{"\x1b[1;6R", "Ctrl+Shift+F3"}, {"\x1b[1;6S", "Ctrl+Shift+F4"},
	{"\x1b[15;6~", "Ctrl+Shift+F5"}, {"\x1b[17;6~", "Ctrl+Shift+F6"},
	{"\x1b[18;6~", "Ctrl+Shift+F7"}, {"\x1b[19;6~", "Ctrl+Shift+F8"},
	{"\x1b[20;6~", "Ctrl+Shift+F9"}, {"\x1b[21;6~", "Ctrl+Shift+F10"},
	{"\x1b[23;6~", "Ctrl+Shift+F11"}, {"\x1b[24;6~", "Ctrl+Shift+F12"},

	{"\x1b[1;8P", "Ctrl+Alt+Shift+F1"}, {"\x1b[1;8Q", "Ctrl+Alt+Shift+F2"},
	{"\x1b[1;8R", "Ctrl+Alt+Shift+F3"}, {"\x1b[1;8S", "Ctrl+Alt+Shift+F4"},
	{"\x1b[15;8~", "Ctrl+Alt+Shift+F5"}, {"\x1b[17;8~", "Ctrl+Alt+Shift+F6"},
	{"\x1b[18;8~", "Ctrl+Alt+Shift+F7"}, {"\x1b[19;8~", "Ctrl+Alt+Shift+F8"},
	{"\x1b[20;8~", "Ctrl+Alt+Shift+F9"}, {"\x1b[21;8~", "Ctrl+Alt+Shift+F10"},
	{"\x1b[23;8~", "Ctrl+Alt+Shift+F11"}, {"\x1b[24;8~", "Ctrl+Alt+Shift+F12"},

	{"\x1b[H", "Home"}, {"\x1b[F", "End"},
	{"\x1b[2~", "Ins"}, {"\x1b[3~", "Del"},
	{"\x1b[5~", "PgUp"}, {"\x1b[6~", "PgDn"},

	{"\x1b[1;3H", "Alt+Home"}, {"\x1b[1;3F", "Alt+End"},
	{"\x1b[2;3~", "Alt+Ins"}, {"\x1b[3;3~", "Alt+Del"},
	{"\x1b[5;3~", "Alt+PgUp"}, {"\x1b[6;3~", "Alt+PgDn"},

	{"\x1b[1;5H", "Ctrl+Home"}, {"\x1b[1;5F", "Ctrl+End"},
	{"\x1b[2;5~", "Ctrl+Ins"}, {"\x1b[3;5~", "Ctrl+Del"},
	{"\x1b[5;5~", "Ctrl+PgUp"}, {"\x1b[6;5~", "Ctrl+PgDn"},

	{"\x1b[1;7H", "Ctrl+Alt+Home"}, {"\x1b[1;7F", "Ctrl+Alt+End"},
	{"\x1b[2;7~", "Ctrl+Alt+Ins"}, {"\x1b[3;7~", "Ctrl+Alt+Del"},
	{"\x1b[5;7~", "Ctrl+Alt+PgUp"}, {"\x1b[6;7~", "Ctrl+Alt+PgDn"},

	{"\x1b[1;4H", "Alt+Shift+Home"}, {"\x1b[1;4F", "Alt+Shift+End"},
	{"\x1b[2;4~", "Alt+Shift+Ins"}, {"\x1b[3;4~", "Alt+Shift+Del"},
	{"\x1b[5;4~", "Alt+Shift+PgUp"}, {"\x1b[6;4~", "Alt+Shift+PgDn"},

	{"\x1b[1;6H", "Ctrl+Shift+Home"}, {"\x1b[1;6F", "Ctrl+Shift+End"},
	{"\x1b[2;6~", "Ctrl+Shift+Ins"}, {"\x1b[3;6~", "Ctrl+Shift+Del"},
	{"\x1b[5;6~", "Ctrl+Shift+PgUp"}, {"\x1b[6;6~", "Ctrl+Shift+PgDn"},

	{"\x1b[1;8H", "Ctrl+Alt+Shift+Home"}, {"\x1b[1;8F", "Ctrl+Alt+Shift+End"},
	{"\x1b[2;8~", "Ctrl+Alt+Shift+Ins"}, {"\x1b[3;8~", "Ctrl+Alt+Shift+Del"},
	{"\x1b[5;8~", "Ctrl+Alt+Shift+PgUp"}, {"\x1b[6;8~", "Ctrl+Alt+Shift+PgDn"},

	{"\x1b[3;2~", "Shift+Del"}, {"\x1b[1;2H", "Shift+Home"},
	{"\x1b[1;2F", "Shift+End"},

	{"\x1b", "Escape"},

//	{"\\C-i", "Tab"}, {"\x1b\\C-i", "Alt+Tab"},
	{"\x1b[Z", "Shift+Tab"},

	/* Note: xterm sends \x7f for Ctrl+Backspace and \C-h for Backspace
	{"\x7f", "Backspace"}, {"\x1b\x7f", "Alt+Backspace"}, */

	/* rxvt-specific */
	{"\x1b[11~", "F1"}, {"\x1b[12~", "F2"},
	{"\x1b[13~", "F3"}, {"\x1b[14~", "F4"},

	{"\x1b[11^", "Ctrl+F1"}, {"\x1b[12^", "Ctrl+F2"},
	{"\x1b[13^", "Ctrl+F3"}, {"\x1b[14^", "Ctrl+F4"},
	{"\x1b[15^", "Ctrl+F5"}, {"\x1b[17^", "Ctrl+F6"},
	{"\x1b[18^", "Ctrl+F7"}, {"\x1b[19^", "Ctrl+F8"},
	{"\x1b[20^", "Ctrl+F9"}, {"\x1b[21^", "Ctrl+F10"},
	{"\x1b[23^", "Ctrl+F11"}, {"\x1b[24^", "Ctrl+F12"},

	{"\x1b[23~", "F11"}, {"\x1b[24~", "F12"},
	{"\x1b[25~", "F13"}, {"\x1b[26~", "F14"},
	{"\x1b[28~", "F15"}, {"\x1b[29~", "F16"},
	{"\x1b[31~", "F17"}, {"\x1b[32~", "F18"},
	{"\x1b[33~", "F19"}, {"\x1b[34~", "F20"},
	{"\x1b[23$", "Shift+F11"}, {"\x1b[24$", "Shift+F12"},

	{"\x1b\x1b[11~", "Alt+F1"}, {"\x1b\x1b[12~", "Alt+F2"},
	{"\x1b\x1b[13~", "Alt+F3"}, {"\x1b\x1b[14~", "Alt+F4"},
	{"\x1b\x1b[15~", "Alt+F5"}, {"\x1b\x1b[17~", "Alt+F6"},
	{"\x1b\x1b[18~", "Alt+F7"}, {"\x1b\x1b[19~", "Alt+F8"},
	{"\x1b\x1b[20~", "Alt+F9"}, {"\x1b\x1b[21~", "Alt+F10"},
	{"\x1b\x1b[23~", "Alt+F11"}, {"\x1b\x1b[24~", "Alt+F12"},

	{"\x1b[23^", "Ctrl+F11"}, {"\x1b[24^", "Ctrl+F12"},
	{"\x1b[25^", "Ctrl+F13"}, {"\x1b[26^", "Ctrl+F14"},
	{"\x1b[28^", "Ctrl+F15"}, {"\x1b[29^", "Ctrl+F16"},
	{"\x1b[31^", "Ctrl+F17"}, {"\x1b[32^", "Ctrl+F18"},
	{"\x1b[33^", "Ctrl+F19"}, {"\x1b[34^", "Ctrl+F20"},
	{"\x1b[23@", "Ctrl+Shift+F11"}, {"\x1b[24@", "Ctrl+Shift+F12"},

	{"\x1b[a", "Shift+Up"}, {"\x1b[b", "Shift+Down"},
	{"\x1b[c", "Shift+Right"}, {"\x1b[d", "Shift+Left"},

	{"\x1b\x1b[A", "Alt+Up"}, {"\x1b\x1b[B", "Alt+Down"},
	{"\x1b\x1b[C", "Alt+Right"}, {"\x1b\x1b[D", "Alt+Left"},

	{"\x1bOa", "Ctrl+Up"}, {"\x1bOb", "Ctrl+Down"},
	{"\x1bOc", "Ctrl+Right"}, {"\x1bOd", "Ctrl+Left"},

	{"\x1b[7~", "Home"}, {"\x1b[8~", "End"},

	{"\x1b\x1b[7~", "Alt+Home"}, {"\x1b\x1b[8~", "Alt+End"},
	{"\x1b\x1b[2~", "Alt+Ins"}, {"\x1b\x1b[3~", "Alt+Del"},
	{"\x1b\x1b[5~", "Alt+PgUp"}, {"\x1b\x1b[6~", "Alt+PgDn"},

	{"\x1b[7^", "Ctrl+Home"}, {"\x1b[8^", "Ctrl+End"},
	{"\x1b[2^", "Ctrl+Ins"}, {"\x1b[3^", "Ctrl+Del"},
	{"\x1b[5^", "Ctrl+PgUp"}, {"\x1b[6^", "Ctrl+PgDn"},

	{"\x1b[7$", "Shift+Home"}, {"\x1b[8$", "Shift+End"},
	{"\x1b[5^", "Ctrl+PgUp"}, {"\x1b[6^", "Ctrl+PgDn"},
	{"\x1b[7^", "Ctrl+Home"}, {"\x1b[8^", "Ctrl+End"},

	{"\x1b\x1b[7^", "Ctrl+Alt+Home"}, {"\x1b\x1b[8^", "Ctrl+Alt+End"},
	{"\x1b\x1b[2^", "Ctrl+Alt+Ins"}, {"\x1b\x1b[3^", "Ctrl+Alt+Del"},
	{"\x1b\x1b[5^", "Ctrl+Alt+PgUp"}, {"\x1b\x1b[6^", "Ctrl+Alt+PgDn"},

	{"\x1b[2@", "Ctrl+Shift+Ins"},	{"\x1b[3@", "Ctrl+Shift+Del"},
	{"\x1b[7@", "Ctrl+Shift+Home"}, {"\x1b[8@", "Ctrl+Shift+End"},

	/* Vte-specific */
	{"\x1b[01;2P", "Shift+F1"}, {"\x1b[01;2Q", "Shift+F2"},
	{"\x1b[01;2R", "Shift+F3"}, {"\x1b[01;2S", "Shift+F4"},

	{"\x1b[01;3P", "Alt+F1"}, {"\x1b[01;3Q", "Alt+F2"},
	{"\x1b[01;3R", "Alt+F3"}, {"\x1b[01;3S", "Alt+F4"},

	{"\x1b[01;5P", "Ctrl+F1"}, {"\x1b[01;5Q", "Ctrl+F2"},
	{"\x1b[01;5R", "Ctrl+F3"}, {"\x1b[01;5S", "Ctrl+F4"},

	{"\x1bOH", "Home"}, {"\x1bOF", "End"},

	/* kitty keyboard protocol */
	{"\x1b[P", "F1"}, {"\x1b[Q", "F2"}, {"\x1b[S", "F4"},

	/* emacs and others */
	{"\x1bOA", "Up"}, {"\x1bOB", "Down"},
	{"\x1bOC", "Right"}, {"\x1bOD", "Left"},
	{"\x1bO5A", "Ctrl+Up"}, {"\x1bO5B", "Ctrl+Down"},
	{"\x1bO5C", "Ctrl+Right"}, {"\x1bO5D", "Ctrl+Left"},

	{"\x1b[5A", "Ctrl+Up"},{"\x1b[5B", "Ctrl+Down"},
	{"\x1b[5C", "Ctrl+Right"},{"\x1b[5D", "Ctrl+Left"},

	{"\x1b[2A", "Shift+Up"}, {"\x1b[2B", "Shift+Down"},
	{"\x1b[2C", "Shift+Right"}, {"\x1b[2D", "Shift+Left"},

	{"\x1b[1~", "Home"}, {"\x1b[4~", "End"},

//	{"\x1b[4h", "Ins"}, {"\x1b[L", "Ctrl+Ins"}, /* st */
//	{"\x1b[M", "Ctrl+Del"},

	/* Let's test the Meta key */
	{"\x1b[6;9~", "Meta+PgDn"}, {"\x1b[1;11F", "Alt+Meta+End"},
	{"\x1b[1;13P", "Ctrl+Meta+F1"}, {"\x1b[3;15~", "Ctrl+Alt+Meta+Del"},
	{"\x1b[19;10~", "Meta+Shift+F8"},

	/* sun-color uses \e[224z-\e[235z for F1-F12 keys. */
	/* cons25 uses \e[M-\e[X for F1-F12 keys. */

	{NULL, NULL},
};

int
key_test(void)
{
	size_t errors = 0;

	for (size_t i = 0; keys[i].key; i++) {
		const size_t key_len = strlen(keys[i].key);
		char *s = malloc((key_len + 1) * sizeof(char));
		if (!s)
			exit(ENOMEM);

		memcpy(s, keys[i].key, key_len + 1);

		char *ret = translate_key(s);
		if (!ret || strcmp(ret, keys[i].translation) != 0) {
			errors++;
			size_t count;
			for (count = 0; keys[i].key[count] == '\x1b'; count++)
				printf("\\e");
			printf("%s (%s): ",  keys[i].key + count, keys[i].translation);

			if (!ret)
				printf("Unknown escape sequence\n");
			else
				printf("%s\n", ret);
		};

		free(ret);
		free(s);
	}

	if (errors == 0)
		printf("All tests passed\n");
	else
		printf("%zu errors\n", errors);

	return 0;
}
#endif /* TK_TEST */
