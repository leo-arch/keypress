/* translate_key.h */

/*
 * Copyright (C) 2025, L. Abramovich <leo.clifm@outlook.com>
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

#ifndef TRANSLATE_KEY_H
#define TRANSLATE_KEY_H

/* Terminal types */
#define TK_TERM_GENERIC    0
#define TK_TERM_LEGACY_SCO (1 << 0)
#define TK_TERM_LEGACY_HP  (1 << 1)
#define TK_TERM_KITTY      (1 << 2)
#define TK_TERM_LINUX      (1 << 3)
/* For the time being, these ones are unused */
#define TK_TERM_XTERM      (1 << 4)
#define TK_TERM_RXVT       (1 << 5)
#define TK_TERM_ST         (1 << 6)

#define ALT_CSI        0x9b /* 8-bit CSI (alternate sequence) */
#define CSI_INTRODUCER 0x5b /* [ */
#define SS3_INTRODUCER 0x4f /* O */

#ifdef __cplusplus
extern "C" {
#endif

char *translate_key(char *str, const int term_type);
int is_end_seq_char(unsigned char c);

#ifdef __cplusplus
}
#endif

#endif /* TRANSLATE_KEY_H */
