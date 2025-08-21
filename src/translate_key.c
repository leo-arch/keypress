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

#include <stdlib.h> /* malloc, free, strtol */
#include <stdio.h>  /* snprintf */
#include <string.h> /* strlen, strcmp, strchr, memcpy, memset */
#include <limits.h> /* INT_MIN, INT_MAX */
#include <ctype.h>  /* toupper() */
#include <errno.h>  /* ENOMEM */

/* When it comes to keyboard escape sequences, we have three kind of
 * terminating characters:
 *
 * 1. Defining the keycode. E.g. 'CSI 1;2D', where 'D' means the key pressed,
 * (Left), and '2' the modifier key (Shift).
 *
 * 2. Defining the modifier key. E.g.: 'CSI 11^', where '^' means the
 * modifier key (Control) and '11' the key pressed (F1).
 *
 * 3. Raw sequence terminator. E.g. 'CSI 15;3~', where '~' simply
 * ends the sequence, '15' is the pressed key (F5), and '3' the modifier
 * key (Alt). */

#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
#define IS_LOWER_ARROW_CHAR(c) ((c) >= 'a' && (c) <= 'd')
#define IS_UPPER_ARROW_CHAR(c) ((c) >= 'A' && (c) <= 'D')
#define IS_ARROW_CHAR(c) (IS_LOWER_ARROW_CHAR((c)) || IS_UPPER_ARROW_CHAR((c)))

#define IS_FOOT_SEQ(s, end) (*(s) == '2' && (s)[1] == '7' && (s)[2] == ';' \
	&& (end) == '~')
#define IS_KITTY_END_CHAR(c)   ((c) == 'u')
#define IS_MODKEY_END_CHAR(c)  ((c) == '^' || (c) == '$' || (c) == '@')
#define IS_GENERIC_END_CHAR(c) ((c) == '~' || (c) == 'z')
#define IS_KEYCODE_END_CHAR(c) (  \
	IS_ARROW_CHAR((c))         || \
	((c) >= 'E' && (c) <= 'H') || \
	((c) >= 'P' && (c) <= 'S') || \
	((c) >= 'j' && (c) <= 'y') || \
	(c) == 'M')

#define ESC_KEY 0x1b

/* Values for modifier keys.
 * See https://en.wikipedia.org/wiki/ANSI_escape_code*/
#define SHIFT_VAL 1
#define ALT_VAL   2
#define CTRL_VAL  4
#define SUPER_VAL 8

/* Some names for control keys. */
static const char *ctrl_keys[256] = {
	[0x7f] = "Del", [0x0d] = "Enter", [0x08] = "Backspace",
	[0x09] = "Tab", [0x20] = "Space", [0x1b] = "Escape",
};

/* The Super key is usually mapped to the Win/logo key (Mod4), for example,
 * on Wayland and Kitty. Mod1 is typically Alt, while Mod2 is NumLock, and
 * Mod5 AltGr (Right Alt). Mod3 is normally left unassigned. */
static const char *mod_table[256] = {
	[SHIFT_VAL] = "Shift",
	[ALT_VAL] = "Alt",
	[CTRL_VAL] = "Ctrl",
	[SUPER_VAL] = "Super",
	[ALT_VAL + SHIFT_VAL] = "Alt+Shift",
	[CTRL_VAL + SHIFT_VAL] = "Ctrl+Shift",
	[SUPER_VAL + SHIFT_VAL] = "Super+Shift",
	[CTRL_VAL + ALT_VAL] = "Ctrl+Alt",
	[CTRL_VAL + ALT_VAL + SHIFT_VAL] = "Ctrl+Alt+Shift",
	[CTRL_VAL + SUPER_VAL] = "Ctrl+Super",
	[ALT_VAL + SUPER_VAL] = "Alt+Super",
	[CTRL_VAL + ALT_VAL + SUPER_VAL] = "Ctrl+Alt+Super",
	[CTRL_VAL + ALT_VAL + SHIFT_VAL + SUPER_VAL] = "Ctrl+Alt+Shift+Super"
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
	['j'] = "KP_Multiply", ['k'] = "KP_Add", ['m'] = "KP_Subtract",
	['M'] = "KP_Enter", ['n'] = "KP_Del", ['o'] = "KP_Divide",
	['p'] = "KP_Ins", ['q'] = "KP_1", ['r'] = "KP_2", ['s'] = "KP_3",
	['t'] = "KP_4", ['u'] = "KP_5", ['v'] = "KP_6", ['w'] = "KP_7",
	['x'] = "KP_8", ['y'] = "KP_9",

	/* Xterm */
	['E'] = "KP_5", ['F'] = "End", ['G'] = "KP_5", ['H'] = "Home",
	['P'] = "F1", ['Q'] = "F2", ['R'] = "F3", ['S'] = "F4",

	/* Sun/Solaris */
	[192] = "F11", [193] = "F12",
	[214] = "Home", [216] = "PgUp", [218] = "KP_5", [220] = "End",
	[222] = "PgDn",
	[224] = "F1", [225] = "F2", [226] = "F3", [227] = "F4", [228] = "F5",
	[229] = "F6", [230] = "F7", [231] = "F8", [232] = "F9", [233] = "F10"
};

struct exceptions_t {
	const char *key;
	const char *name;
};

/* A list of escape sequences missed by our identifying algorithms, mostly
 * because they deviate from Xterm and Rxvt protocols. */
static const struct exceptions_t exceptions[] = {
	/* Linux console */
	/* Using A-D (almost universally used for arrow keys) for function keys
	 * is confusing, to say the least. */
	{"\x1b[[A", "F1"}, {"\x1b[[B", "F2"}, {"\x1b[[C", "F3"},
	{"\x1b[[D", "F4"}, {"\x1b[[E", "F5"},

	/* St
	 * Keycodes and modifiers are not used consistently. For example,
	 * "CSI 2J" is Shift+Home: '2' for Shift and 'J' for Home. But,
	 * "CSI J" is Ctrl+End: no modifier (it should be '5') and 'J' is not
	 * Home anymore, but Del.
	 * Also, while "CSI P", is Del, "CSI 2K" is Shift+Del and "CSI K" is Shift+End.
	 * Also, while "CSI L" is Ctrl+Ins, "CSI 4l" is Shift+Ins. */
	{"\x1b[4h", "Ins"}, {"\x1b[M", "Ctrl+Del"}, {"\x1b[L", "Ctrl+Ins"},
	{"\x1b[2J", "Shift+Home"}, {"\x1b[K", "Shift+End"},
	{"\x1b[2K", "Shift+Del"}, {"\x1b[J", "Ctrl+End"},
	{"\x1b[4l", "Shift+Ins"},
	/* This is F1 in Kitty, forget about it.
	{"\x1b[P", "Del"}, */
	{NULL, NULL}
};

struct ext_key_map_t {
	int code;
	const char *name;
};

/* An extended list of key symbols and their corresponding key codes.
 * This includes control characters, just as Kitty and Foot extended keys. */
static const struct ext_key_map_t ext_key_map[] = {
	{0, "NULL"}, {1, "SOH"}, {2, "STX"}, {3, "ETX"}, {4, "EOT"},
	{5, "ENQ"}, {6, "ACK"}, {7, "BELL"}, {8, "Backspace"}, {9, "Tab"},
	{10, "LF"}, {11, "VT"}, {12, "FF"}, {13, "Enter"}, {14, "SO"},
	{15, "SI"}, {16, "DLE"}, {17, "DC1"}, {18, "DC2"}, {19, "DC3"},
	{20, "DC4"}, {21, "NAK"}, {22, "SYN"}, {23, "ETB"}, {24, "CAN"},
	{25, "EM"}, {26, "SUB"}, {27, "Escape"}, {28, "FS"}, {29, "GS"},
	{30, "RS"}, {31, "US"}, {32, "Space"}, {127, "Del"},
	{160, "NBSP"}, {173, "SHY"},

	/* Kitty / extended keys */
	{57358, "CapsLock"}, {57359, "ScrollLock"}, {57360, "NumLock"},
	{57361, "PrtScr"}, {57362, "Pause"}, {57363, "Menu"},
	{57376, "F13"}, {57377, "F14"}, {57378, "F15"}, {57379, "F16"},
	{57380, "F17"}, {57381, "F18"}, {57382, "F19"}, {57383, "F20"},
	{57384, "F21"}, {57385, "F22"}, {57386, "F23"}, {57387, "F24"},
	{57388, "F25"}, {57389, "F26"}, {57390, "F27"}, {57391, "F28"},
	{57392, "F29"}, {57393, "F30"}, {57394, "F31"}, {57395, "F32"},
	{57396, "F33"}, {57397, "F34"}, {57398, "F35"}, {57399, "KP_0"},
	{57400, "KP_1"}, {57401, "KP_2"}, {57402, "KP_3"}, {57403, "KP_4"},
	{57404, "KP_5"}, {57405, "KP_6"}, {57406, "KP_7"}, {57407, "KP_8"},
	{57408, "KP_9"}, {57409, "KP_Decimal"}, {57410, "KP_Divide"},
	{57411, "KP_Multiply"}, {57412, "KP_Subtract"}, {57413, "KP_Add"},
	{57414, "KP_Enter"}, {57415, "KP_Equals"}, {57416, "KP_Separator"},
	{57417, "KP_Left"}, {57418, "KP_Right"}, {57419, "KP_Up"},
	{57420, "KP_Down"}, {57421, "KP_PgUp"}, {57422, "KP_PgDn"},
	{57423, "KP_Home"}, {57424, "KP_End"}, {57425, "KP_Insert"},
	{57426, "KP_Delete"}, {57427, "KP_Begin"}, {57428, "MediaPlay"},
	{57429, "MediaPause"}, {57430, "MediaPlayPause"}, {57431, "MediaReverse"},
	{57432, "MediaStop"}, {57433, "MediaFastForward"}, {57434, "MediaRewind"},
	{57435, "MediaTrackNext"}, {57436, "MediaTrackPrevious"},
	{57437, "MediaRecord"}, {57438, "VolumeDown"}, {57439, "VolumeUp"},
	{57440, "VolumeMute"}, {57441, "LShift"}, {57442, "LControl"},
	{57443, "LAlt"}, {57444, "LSuper"}, {57445, "LHyper"}, {57446, "LMeta"},
	{57447, "RShift"}, {57448, "RControl"}, {57449, "RAlt"},
	{57450, "RSuper"}, {57451, "RHyper"}, {57452, "RMeta"},
	{57453, "ISO_Level3_Shift"}, {57454, "ISO_Level5_Shift"},

	/* Foot */
	{65450, "KP_Multiply"}, {65451, "KP_Add"}, {65453, "KP_Subtract"},
	{65454, "KP_Delete"}, {65455, "KP_Divide"}, {65456, "KP_Insert"},
	{65457, "KP_End"}, {65465, "KP_PgUp"},

	{0, NULL}
};

/* A safe atoi */
static int
xatoi(const char *str)
{
	if (!str || !*str)
		return 0;

	char *endptr = NULL;
	const long n = strtol(str, &endptr, 10);

	if (endptr == str)
		return 0;

	if (n > INT_MAX) return INT_MAX;
	if (n < INT_MIN) return INT_MIN;
	return (int)n;
}

/* Return the translated key for the escape sequence STR looking in the
 * exceptions list. If none is found, NULL is returned. */
static char *
check_exceptions(const char *str)
{
	for (size_t i = 0; exceptions[i].key; i++) {
		if (strcmp(exceptions[i].key, str) == 0) {
			const size_t len = strlen(exceptions[i].name);
			char *p = malloc((len + 1) * sizeof(char));
			if (!p)
				return NULL;
			memcpy(p, exceptions[i].name, len + 1);
			return p;
		}
	}

	return NULL;
}

/* Return 1 if the byte C ends a keyboard escape sequence, or 0 otherwise. */
int
is_end_seq_char(unsigned char c)
{
	return (c != 0x1b /* First byte of an escape sequence */
		&& c != '[' && c != 'O' /* CSI and SS3 introducers */
		&& ((c >= 0x40 && c <= 0x7e) /* ECMA-48 terminating bytes */
		|| c == '$')); /* Rxvt uses this (E.g. "CSI 24$" for Shift+F12) */
}

/* Rxvt uses '$', '@', and '^' to indicate the modifier key. */
static void
set_end_char_is_mod_key(char *str, const size_t end, int *keycode, int *mod_key)
{
	if (str[end] == '$')
		*mod_key += SHIFT_VAL;
	else
		*mod_key += CTRL_VAL + (str[end] == '@');

	str[end] = '\0';

	if (*str == ESC_KEY) { /* Rxvt */
		*mod_key += ALT_VAL;
		str += 2;
	}

	*keycode = xatoi(str);
}

/* The terminating character just terminates the string. Mostly '~', but
 * also 'z' is Sun/Solaris terminals. In this case, the pressed key and
 * the modifier key are defined as parameters in the sequence. */
static void
set_end_char_is_generic(char *str, const size_t end, int *keycode, int *mod_key)
{
	str[end] = '\0';
	if (*str == ESC_KEY) { /* Rxvt */
		*mod_key += ALT_VAL;
		*keycode = xatoi(str + 2);
	} else {
		char *s = strchr(str, ';');
		if (s) *s = '\0';
		*keycode = xatoi(str);
		*mod_key += (s && s[1]) ? xatoi(s + 1) - 1 : 0;
	}
}

static void
set_end_char_is_keycode_no_arrow(char *str, const size_t end, int *keycode,
	int *mod_key)
{
	*keycode = str[end];
	char *s = strchr(str, ';');
	str[end] = '\0';

	if (s) {
		*mod_key += (s && s[1]) ? xatoi(s + 1) - 1 : 0;
	} else {
		if (*str == 'O') /* Contour (SS3 mod key) */
			str++;
		*mod_key += *str ? xatoi(str) - 1 : 0;
	}
}

/* The terminating character desginates the key pressed. Mostly arrow keys
 * (e.g. CSI D) for the Left key. */
static void
set_end_char_is_keycode(char *str, size_t end, int *keycode, int *mod_key)
{
	if (!IS_ARROW_CHAR(str[end])) {
		set_end_char_is_keycode_no_arrow(str, end, keycode, mod_key);
		return;
	}

	*keycode = str[end];
	if (*str == ESC_KEY) { /* Rxvt */
		*mod_key += ALT_VAL;
		str++;
		end--;
	}

	char *s = strchr(str, ';');
	if (s) {
		str[end] = '\0';
		*mod_key += (s && s[1]) ? xatoi(s + 1) - 1 : 0;
	} else if (IS_LOWER_ARROW_CHAR(str[end])) { /* Rxvt */
		if (*str == 'O')
			*mod_key += CTRL_VAL;
		else
			(*mod_key)++;
	} else if (IS_UPPER_ARROW_CHAR(str[end])) {
		str[end] = '\0';
		if (*str == 'O')
			str++;
		if (IS_DIGIT(*str))
			*mod_key += xatoi(str) - 1;
	}
}

/* Max output string length */
#define MAX_BUF 256

static char *
print_non_esc_seq(const char *str)
{
	char *buf = malloc(MAX_BUF * sizeof(char));
	if (!buf)
		return NULL;

	if (!str || !*str) {
		free(buf);
		return NULL;
	}

	const unsigned char *s = (const unsigned char *)str;

	if (s[1]) {
		snprintf(buf, MAX_BUF, "%s", s); /* A string, not a byte */
	} else if (ctrl_keys[*s]) { /* Backspace, Tab, Enter, Space, Del */
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[*s]);
	} else if (*s < 0x20) { /* Control characters */
		snprintf(buf, MAX_BUF, "%s%c", "Ctrl+", *s + '@');
	} else {
		free(buf);
		return NULL;
	}

	return buf;
}

static char *
check_single_key(char *str, const int csi_seq)
{
	char *buf = malloc(MAX_BUF * sizeof(char));
	if (!buf)
		return NULL;

	if (!*str) {
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[(unsigned char)ESC_KEY]);
		return buf;
	}

	if (str[1]) {
		free(buf);
		return NULL;
	}

	if (*str == 'Z') {
		snprintf(buf, MAX_BUF, "%s", "Shift+Tab");
		return buf;
	}

	if (csi_seq == 0) {
		unsigned char *s = (unsigned char *)str;
		if (ctrl_keys[*s]) /* Backspace, Tab, Enter, Space, Del */
			snprintf(buf, MAX_BUF, "Alt+%s", ctrl_keys[*s]);
		else if (*s < 0x20)
			snprintf(buf, MAX_BUF, "Ctrl+Alt+%c", *s + '@');
		else
			snprintf(buf, MAX_BUF, "Alt+%c", toupper(*s));
		return buf;
	}

	free(buf);
	return NULL;
}
#undef MAX_BUF

static char *
write_translation(const int keycode, const int mod_key)
{
	const char *k = (keycode >= 0 && keycode <= 255)
		? key_table[(unsigned char)keycode] : NULL;
	const char *m = (mod_key >= 0 && mod_key <= 255)
		? mod_table[(unsigned char)mod_key] : NULL;

	if (!k)
		return NULL;

	const size_t len = (m ? strlen(m) : 0) + (k ? strlen(k) : 0) + 2;
	char *buf = malloc(len * sizeof(char));
	if (!buf)
		return NULL;

	if (m)
		snprintf(buf, len, "%s+%s", m, k);
	else
		snprintf(buf, len, "%s", k);

	return buf;
}

static const char *
get_ext_key_symbol(const int keycode)
{
	static char keysym_str[2] = {0};

	/* These are directly printable */
	if (keycode > 32 && keycode <= 126) {
		keysym_str[0] = (char)toupper(keycode);
		return keysym_str;
	}

	/* Linear search through ext_key_map */
	for (size_t i = 0; ext_key_map[i].name != NULL; i++) {
		if (ext_key_map[i].code == keycode)
			return ext_key_map[i].name;
	}

	/* Transform UTF-8 codepoint to a string of bytes. */
	static char str[5] = "";
	memset(str, 0, sizeof(str));

	if (keycode <= 0x7ff) {
		str[0] = 0xC0 | (keycode >> 6);
		str[1] = 0x80 | (keycode & 0x3F);
	} else if (keycode <= 0x7fff) {
		str[0] = 0xE0 | (keycode >> 12);
		str[1] = 0x80 | ((keycode >> 6) & 0x3F);
		str[2] = 0x80 | (keycode & 0x3F);
	} else if (keycode <= 0x10FFFF) {
		str[0] = 0xF0 | (keycode >> 18);
		str[1] = 0x80 | ((keycode >> 12) & 0x3F);
		str[2] = 0x80 | ((keycode >> 6) & 0x3F);
		str[3] = 0x80 | (keycode & 0x3F);
	} else {
		return "UNKNOWN";
	}

	return str;
}

/* Translate the modifier number MOD_NUM into human-readable form. */
static const char *
get_kitty_mod_symbol(const int mod_key)
{
	/* The biggest value mod_key can take is 255 (since
	 * 1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 = 255). In this case, the modifier
	 * string would be "Shift+Alt+Ctrl+Super+Hyper+Meta+CapsLock+NumLock-",
	 * which is 50 bytes long, including the terminating NUL byte. */
	static char mod[64];
	memset(mod, '\0', sizeof(mod));

	const int m = mod_key;
	const size_t s = sizeof(mod);
	int l = 0;

	if (m & 4) l += snprintf(mod + l, s - (size_t)l, "Ctrl+");
	if (m & 2) l += snprintf(mod + l, s - (size_t)l, "Alt+");
	if (m & 1) l += snprintf(mod + l, s - (size_t)l, "Shift+");
	if (m & 8) l += snprintf(mod + l, s - (size_t)l, "Super+");
	if (m & 16) l += snprintf(mod + l, s - (size_t)l, "Hyper+");
	if (m & 32) l += snprintf(mod + l, s - (size_t)l, "Meta+");
	if (m & 64) l += snprintf(mod + l, s - (size_t)l, "CapsLock+");
	if (m & 128) snprintf(mod + l, s - (size_t)l, "NumLock+");

	return mod;
}

static char *
write_kitty_keys(char *str, const size_t end)
{
	str[end] = '\0';

	int keycode = -1;
	int mod_key = 0;

	char *delim = strchr(str, ';');
	if (delim) {
		*delim = '\0';
		keycode = xatoi(str);
		mod_key = delim[1] ? xatoi(delim + 1) - 1 : 0;
	} else {
		keycode = xatoi(str);
	}

	const char *k = keycode != -1 ? get_ext_key_symbol(keycode) : NULL;
	const char *m = mod_key != 0 ? get_kitty_mod_symbol(mod_key) : NULL;

	if (!k)
		return NULL;

	const size_t buf_len = strlen(k) + (m ? strlen(m) : 0) + 1;
	char *buf = malloc(buf_len * sizeof(char));
	if (!buf)
		return NULL;

	snprintf(buf, buf_len, "%s%s", m ?  m : "", k);
	return buf;
}

/* A Foot sequence is "CSI 27;mod;key~"
 * See https://codeberg.org/dnkl/foot/src/branch/master/keymap.h*/
static char *
write_foot_seq(char *str, const size_t end)
{
	str[end] = '\0';
	str += 3; /* Skip "27;" */
	char *s = strchr(str, ';');
	if (!s)
		return NULL;

	*s = '\0';
	const int mod_key = xatoi(str) - 1;
	const int keycode = xatoi(s + 1);
	const char *k = get_ext_key_symbol(keycode);
	const char *m = (mod_key >= 0 && mod_key <= 255)
		? mod_table[(unsigned char)mod_key] : NULL;

	const size_t len = (m ? strlen(m) : 0) + (k ? strlen(k) : 0) + 2;
	char *buf = malloc(len * sizeof(char));
	if (!buf)
		return NULL;

	snprintf(buf, len, "%s%s%s", m ? m : "", m ? "+" : "", k);
	return buf;
}

/* Translate the escape sequence STR into the corresponding symbolic value.
 * E.g. "\x1b[1;7D" will return "Ctrl+Alt+Left". If no symbolic value is
 * found, NULL is returned.
 * The returned value, if not NULL, is dinamically allocated and must be
 * free'd by the caller.
 *
 * NOTE: This function assumes STR comes directly from the terminal, i.e. by
 * reading terminal input in raw mode. User suplied input, therefore, will
 * return false positives. */
char *
translate_key(char *str)
{
	if (!str || !*str)
		return NULL;

	if (*str != ESC_KEY)
		return print_non_esc_seq(str);

	char *buf = check_exceptions(str);
	if (buf)
		return buf;

	const int csi_seq = str[1] == '[';
	str += str[1] == '[' ? 2 : 1;

	buf = check_single_key(str, csi_seq);
	if (buf)
		return buf;

	int keycode = -1;
	int mod_key = 0;

	const size_t len = strlen(str);
	const size_t end = len > 0 ? len - 1 : len;

	const char end_char = str[end];

	if (IS_KITTY_END_CHAR(end_char) && csi_seq == 1)
		return write_kitty_keys(str, end);

	if (IS_FOOT_SEQ(str, end_char) && csi_seq == 1)
		return write_foot_seq(str, end);

	else if (IS_MODKEY_END_CHAR(end_char))
		set_end_char_is_mod_key(str, end, &keycode, &mod_key);
	else if (IS_KEYCODE_END_CHAR(end_char))
		set_end_char_is_keycode(str, end, &keycode, &mod_key);
	else if (IS_GENERIC_END_CHAR(end_char))
		set_end_char_is_generic(str, end, &keycode, &mod_key);
	else
		return NULL;

	return write_translation(keycode, mod_key);
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

	{"\x09", "Tab"}, {"\x1b\x09", "Alt+Tab"}, {"\x1b[Z", "Shift+Tab"},

	{"\x7f", "Del"}, {"\x1b\x7f", "Alt+Del"},

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

	/* st */
	{"\x1b[4h", "Ins"}, {"\x1b[L", "Ctrl+Ins"},
	{"\x1b[M", "Ctrl+Del"},

	/* Linux console */
	{"\x1b[[A", "F1"}, {"\x1b[[E", "F5"},

	/* Let's test the Super key */
	{"\x1b[6;9~", "Super+PgDn"}, {"\x1b[1;11F", "Alt+Super+End"},
	{"\x1b[1;13P", "Ctrl+Super+F1"}, {"\x1b[3;15~", "Ctrl+Alt+Super+Del"},
	{"\x1b[19;10~", "Super+Shift+F8"},

	/* Sun/Solaris */
	{"\x1b[224z", "F1"}, {"\x1b[214;7z", "Ctrl+Alt+Home"}, {"\x1b[2z", "Ins"},

	/* Kitty protocol */
	{"\x1b[57425u", "KP_Insert"}, {"\x1b[118;3u", "Alt+V"},
	{"\x1b[106;7u", "Ctrl+Alt+J"},

	/* Foot */
	{"\x1b[27;5;13~", "Ctrl+Enter"}, {"\x1b[27;5;49~", "Ctrl+1"},
	{"\x1b[27;9;9~", "Super+Tab"}, {"\x1b[27;5;65450~", "Ctrl+KP_Multiply"},

	/* Contour */
	{"\x1b[O6P", "Ctrl+Shift+F1"},

	/* cons25 uses \e[M-\e[X for F1-F12 keys. */

	{NULL, NULL},
};

int
key_test(void)
{
	size_t errors = 0;
	size_t i;

	for (i = 0; keys[i].key; i++) {
		const size_t key_len = strlen(keys[i].key);
		char *s = malloc((key_len + 1) * sizeof(char));
		if (!s)
			return -ENOMEM;

		memcpy(s, keys[i].key, key_len + 1);

		char *ret = translate_key(s);
		if (!ret || strcmp(ret, keys[i].translation) != 0) {
			errors++;
			size_t count;
			for (count = 0; keys[i].key[count] == ESC_KEY; count++)
				printf("\\e");
			printf("%s (%s): ",  keys[i].key + count, keys[i].translation);

			if (!ret)
				puts("Unknown escape sequence");
			else
				printf("%s\n", ret);
		};

		free(ret);
		free(s);
	}

	printf("Performed %zu tests: %zu errors\n", i, errors);

	return (errors > 0);
}
#endif /* TK_TEST */
