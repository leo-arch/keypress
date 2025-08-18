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

/* When it comes to keyboard escape sequences, we have three kind of
 * terminating characters:
 *
 * 1. Defining the keycode. E.g. '\x1b[1;2D', where 'D' means the key pressed,
 * (Left), and '2' the modifier key (Shift).
 *
 * 2. Defining the modifier key. E.g.: '\x1b[11^', where '^' means the
 * modifier key (Control) and '11' the key pressed (F1).
 *
 * 3. Raw sequence terminator. E.g. '\x1b[15;3~', where '~' simply
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
#define META_VAL  8

/* Max output string length */
#define MAX_BUF 256

/* Return 1 if the byte C ends a keyboard escape sequence, or 0 otherwise. */
int
is_end_seq_char(char c)
{
	return (IS_KEYCODE_END_CHAR(c) || IS_MODKEY_END_CHAR(c)
		|| IS_GENERIC_END_CHAR(c) || IS_KITTY_END_CHAR(c)
		|| (c) == 'Z'); /* 'Z' required for Shift-Tab (\\e[Z) */
}

/* Some names for control keys. */
static const char *ctrl_keys[256] = {
	[0x7f] = "Del", [0x0d] = "Enter", [0x08] = "Backspace",
	[0x09] = "Tab", [0x20] = "Space", [0x1b] = "Escape",
};

/* The Meta key is usually mapped to the Super/logo key (Mod4), for example,
 * on Wayland. Mod1 is typically Alt, while Mod2 is NumLock, and Mod5 AltGr
 * (Right Alt). Mod3 is normally left unassigned. */
static const char *mod_table[256] = {
	[SHIFT_VAL] = "Shift",
	[ALT_VAL] = "Alt",
	[CTRL_VAL] = "Ctrl",
	[META_VAL] = "Meta",
	[ALT_VAL + SHIFT_VAL] = "Alt+Shift",
	[CTRL_VAL + SHIFT_VAL] = "Ctrl+Shift",
	[META_VAL + SHIFT_VAL] = "Meta+Shift",
	[CTRL_VAL + ALT_VAL] = "Ctrl+Alt",
	[CTRL_VAL + ALT_VAL + SHIFT_VAL] = "Ctrl+Alt+Shift",
	[CTRL_VAL + META_VAL] = "Ctrl+Meta",
	[ALT_VAL + META_VAL] = "Alt+Meta",
	[CTRL_VAL + ALT_VAL + META_VAL] = "Ctrl+Alt+Meta",
	[CTRL_VAL + ALT_VAL + SHIFT_VAL + META_VAL] = "Ctrl+Alt+Shift+Meta"
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

/* A list of escape sequences missed by our identifying algorithms. */
static const struct exceptions_t exceptions[] = {
	/* Linux console */
	{"\x1b[[A", "F1"}, {"\x1b[[B", "F2"}, {"\x1b[[C", "F3"},
	{"\x1b[[D", "F4"}, {"\x1b[[E", "F5"},

	/* st */
	{"\x1b[4h", "Ins"}, {"\x1b[M", "Ctrl+Del"}, {"\x1b[L", "Ctrl+Ins"},
	{NULL, NULL}
};

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
				exit(ENOMEM);
			memcpy(p, exceptions[i].name, len + 1);
			return p;
		}
	}

	return NULL;
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

	*keycode = atoi(str);
}

/* The terminating character just tetrminates the string. Mostly '~', but
 * also 'z' is Sun/Solaris terminals. In this case, the pressed key and
 * the modifier key are defined as parameters in the sequence. */
static void
set_end_char_is_generic(char *str, const size_t end, int *keycode, int *mod_key)
{
	str[end] = '\0';
	if (*str == ESC_KEY) { /* Rxvt */
		*mod_key += ALT_VAL;
		*keycode = atoi(str + 2);
	} else {
		char *s = strchr(str, ';');
		if (s) *s = '\0';
		*keycode = atoi(str);
		*mod_key += (s && s[1]) ? atoi(s + 1) - 1 : 0;
	}
}

static void
set_end_char_is_keycode_no_arrow(char *str, const size_t end, int *keycode,
	int *mod_key)
{
	*keycode = str[end];
	char *s = strchr(str, ';');
	if (s) {
		str[end] = '\0';
		*mod_key += (s && s[1]) ? atoi(s + 1) - 1 : 0;
	}
}

/* The terminating character desginates the key pressed. Mostly arrow keys
 * (e.g. \\e[D) for the Left key. */
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
		*mod_key += (s && s[1]) ? atoi(s + 1) - 1 : 0;
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
			*mod_key += atoi(str) - 1;
	}
}

static char *
print_non_esc_seq(const char *str)
{
	char *buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (!str || !*str)
		return NULL;

	if (str[1])
		snprintf(buf, MAX_BUF, "%s", str);
	else if (*str == 0x08)
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[(int)*str]);
	else if (*str == 0x09)
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[(int)*str]);
	else if (*str == 0x0d)
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[(int)*str]);
	else if (*str == 0x20)
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[(int)*str]);
	else if (*str == 0x7f)
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[(int)*str]);
	else if (*str < 0x20)
		snprintf(buf, MAX_BUF, "%s%c", "Ctrl+", *str + '@');
	else
		return NULL;

	return buf;
}

static char *
check_single_key(char *str, const int csi_seq)
{
	char *buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (!*str) {
		snprintf(buf, MAX_BUF, "%s", ctrl_keys[ESC_KEY]);
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
		if (*str == 0x08 || *str == 0x7f || *str == 0x09 || *str == 0x0d)
			snprintf(buf, MAX_BUF, "Alt+%s", ctrl_keys[(int)*str]);
		else if (*str < 0x20)
			snprintf(buf, MAX_BUF, "%s%c", "Ctrl+Alt+", *str + '@');
		else
			snprintf(buf, MAX_BUF, "%s%c", "Alt+", toupper(*str));
		return buf;
	}

	free(buf);
	return NULL;
}

static char *
write_translation(const int keycode, const int mod_key)
{
	const char *k = (keycode >= 0 && keycode <= 255) ? key_table[keycode] : NULL;
	const char *m = (mod_key >= 0 && mod_key <= 255) ? mod_table[mod_key] : NULL;

	if (!k)
		return NULL;

	char *buf = malloc((MAX_BUF + 1) * sizeof(char));
	if (!buf)
		exit(ENOMEM);

	if (m)
		snprintf(buf, MAX_BUF, "%s+%s", m, k);
	else
		snprintf(buf, MAX_BUF, "%s", k);

	return buf;
}

static const char *
get_kitty_key_symbol(const int keycode)
{
	static char keysym_str[2] = {0};

	/* These are directly printable */
	if (keycode > 32 && keycode < 256 && keycode != 127
	&& keycode != 160 && keycode != 173) {
		keysym_str[0] = (char)toupper(keycode);
		return keysym_str;
	}

	switch (keycode) {
	/* Control keys */
	case 0: return "NULL"; case 1: return "SOH"; case 2: return "STX";
	case 3: return "ETX"; case 4: return "EOT"; case 5: return "ENQ";
	case 6: return "ACK"; case 7: return "BELL"; case 8: return "Backspace";
	case 9: return "Tab"; case 10: return "LF"; case 11: return "VT";
	case 12: return "FF"; case 13: return "Enter"; case 14: return "SO";
	case 15: return "SI"; case 16: return "DLE"; case 17: return "DC1";
	case 18: return "DC2"; case 19: return "DC3"; case 20: return "DC4";
	case 21: return "NAK"; case 22: return "SYN"; case 23: return "ETB";
	case 24: return "CAN"; case 25: return "EM"; case 26: return "SUB";
	case 27: return "Escape"; case 28: return "FS"; case 29: return "GS";
	case 30: return "RS"; case 31: return "US";

	/* Non-printable regular keys */
	case 32: return "Space"; case 127: return "Del";
	case 160: return "NSBP"; case 173: return "SHY";

	/* Special keyboard keys */
	case 57358: return "CapsLock"; case 57359: return "ScrollLock";
	case 57360: return "NumLock"; case 57361: return "PrtScr";
	case 57362: return "Pause"; case 57363: return "Menu";
	case 57376: return "F13"; case 57377: return "F14";
	case 57378: return "F15"; case 57379: return "F16";
	case 57380: return "F17"; case 57381: return "F18";
	case 57382: return "F19"; case 57383: return "F20";
	case 57384: return "F21"; case 57385: return "F22";
	case 57386: return "F23"; case 57387: return "F24";
	case 57388: return "F25"; case 57389: return "F26";
	case 57390: return "F27"; case 57391: return "F28";
	case 57392: return "F29"; case 57393: return "F30";
	case 57394: return "F31"; case 57395: return "F32";
	case 57396: return "F33"; case 57397: return "F34";
	case 57398: return "F35"; case 57399: return "KP_0";
	case 57400: return "KP_1"; case 57401: return "KP_2";
	case 57402: return "KP_3"; case 57403: return "KP_4";
	case 57404: return "KP_5"; case 57405: return "KP_6";
	case 57406: return "KP_7"; case 57407: return "KP_8";
	case 57408: return "KP_9"; case 57409: return "KP_Decimal";
	case 57410: return "KP_Divide"; case 57411: return "KP_Multiply";
	case 57412: return "KP_Subtract"; case 57413: return "KP_Add";
	case 57414: return "KP_Enter"; case 57415: return "KP_Equals";
	case 57416: return "KP_Separator"; case 57417: return "KP_Left";
	case 57418: return "KP_Right"; case 57419: return "KP_Up";
	case 57420: return "KP_Down"; case 57421: return "KP_PageUp";
	case 57422: return "KP_PageDown"; case 57423: return "KP_Home";
	case 57424: return "KP_End"; case 57425: return "KP_Insert";
	case 57426: return "KP_Delete"; case 57427: return "KP_Begin";
	case 57428: return "MediaPlay"; case 57429: return "MediaPause";
	case 57430: return "MediaPlayPause"; case 57431: return "MediaReverse";
	case 57432: return "MediaStop"; case 57433: return "MediaFastForward";
	case 57434: return "MediaRewind"; case 57435: return "MediaTrackNext";
	case 57436: return "MediaTrackPrevious"; case 57437: return "MediaRecord";
	case 57438: return "VolumeDown"; case 57439: return "VolumeUp";
	case 57440: return "VolumeMute"; case 57441: return "LShift";
	case 57442: return "LControl"; case 57443: return "LAlt";
	case 57444: return "LSuper"; case 57445: return "LHyper";
	case 57446: return "LMeta"; case 57447: return "RShift";
	case 57448: return "RControl"; case 57449: return "RAlt";
	case 57450: return "RSuper"; case 57451: return "RHyper";
	case 57452: return "RMeta"; case 57453: return "ISO_Level3_Shift";
	case 57454: return "ISO_Level5_Shift";

	default: return "UNKNOWN";
	}
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
		keycode = atoi(str);
		mod_key = delim[1] ? atoi(delim + 1) - 1 : 0;
	} else {
		keycode = atoi(str);
	}

	const char *k = keycode != -1 ? get_kitty_key_symbol(keycode) : NULL;
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

/* A Foot sequence is "CSI 27;mod;key~" */
static char *
write_foot_seq(char *str, const size_t end)
{
	str[end] = '\0';
	str += 3; // Skip "27;"
	char *s = strchr(str, ';');
	if (!s)
		return NULL;

	*s = '\0';
	const int mod_key = atoi(str) - 1;
	const int keycode = atoi(s + 1);
	const char *k = get_kitty_key_symbol(keycode);
	const char *m = (mod_key >= 0 && mod_key <= 255) ? mod_table[mod_key] : NULL;

	char *buf = malloc(MAX_BUF * sizeof(char));
	if (!buf)
		return NULL;

	snprintf(buf, MAX_BUF, "%s%s%s", m ? m : "", m ? "+" : "", k);
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

	size_t len = strlen(str);
	size_t end = len > 0 ? len - 1 : len;

	const char end_char = str[end];

	if (IS_KITTY_END_CHAR(end_char) && csi_seq == 1)
		return write_kitty_keys(str, end);

	if (IS_FOOT_SEQ(str, end_char))
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

	{"\x09", "Ctrl+I"}, /* Tab */
	{"\x1b\x09", "Ctrl+Alt+I"}, /* Alt+Tab */
	{"\x1b[Z", "Shift+Tab"},

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

	/* Let's test the Meta key */
	{"\x1b[6;9~", "Meta+PgDn"}, {"\x1b[1;11F", "Alt+Meta+End"},
	{"\x1b[1;13P", "Ctrl+Meta+F1"}, {"\x1b[3;15~", "Ctrl+Alt+Meta+Del"},
	{"\x1b[19;10~", "Meta+Shift+F8"},

	/* Sun/Solaris */
	{"\x1b[224z", "F1"}, {"\x1b[214;7z", "Ctrl+Alt+Home"}, {"\x1b[2z", "Ins"},

	/* Kitty protocol */
	{"\x1b[57425u", "KP_Insert"}, {"\x1b[118;3u", "Alt+V"},
	{"\x1b[106;7u", "Ctrl+Alt+J"},

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
