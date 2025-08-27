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

/* test.c */

#include <stdio.h>  // printf & co
#include <stdlib.h> // malloc
#include <string.h> // strlen
#include <errno.h>  // ENOMEM

#include "../src/translate_key.h" // translate_key

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
	{"\x1b[6;9~", "Super+PgDn"}, {"\x1b[1;11F", "Super+Alt+End"},
	{"\x1b[1;13P", "Super+Ctrl+F1"}, {"\x1b[3;15~", "Super+Ctrl+Alt+Del"},
	{"\x1b[19;10~", "Super+Shift+F8"},

	/* Sun/Solaris */
	{"\x1b[224z", "F1"}, {"\x1b[214;7z", "Ctrl+Alt+Home"}, {"\x1b[2z", "Ins"},

	/* Kitty protocol */
	{"\x1b[57425u", "KP_Insert"}, {"\x1b[118;3u", "Alt+v"},
	{"\x1b[106;7u", "Ctrl+Alt+j"},

	/* Xterm  (with modifyOtherKeys enabled) */
	{"\x1b[27;5;13~", "Ctrl+Enter"}, {"\x1b[27;5;49~", "Ctrl+1"},
	{"\x1b[27;9;9~", "Super+Tab"}, {"\x1b[27;5;65450~", "Ctrl+KP_Multiply"},

	/* Contour */
	{"\x1b[O6P", "Ctrl+Shift+F1"},

	/* UTF-8 */
	{"\xf0\x9f\x98\x80", "😀"}, {"\xf0\x9f\x8c\x80", "🌀"},
	{"\xf0\x9f\x91\xa6", "👦"},

	/* 8-bit CSI */
	{"\x9b\x41", "Up"},

	/* cons25 uses \e[M-\e[X for F1-F12 keys. */

	{NULL, NULL},
};

#define ESC_KEY 0x27
int
main(int argc, char **argv)
{
	(void)argc;
	(void)(argv);

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
			for (size_t j = 0; keys[i].key[j]; j++) {
				if (keys[i].key[j] < 0x31)
					printf("%d", keys[i].key[j]);
				else
					printf("%c", keys[i].key[j]);
			}

			if (!ret)
				puts(": Unknown escape sequence");
			else
				printf(": %s != %s\n", ret, keys[i].translation);
		};

		free(ret);
		free(s);
	}

	printf("Performed %zu tests: %zu errors\n", i, errors);

	return (errors > 0);
}
