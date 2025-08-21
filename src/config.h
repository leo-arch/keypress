/* config.h */

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

#define DEFAULT_CLEAR_SCREEN 0
#define DEFAULT_COLOR 1
#define DEFAULT_TRANSLATE NULL
#define DEFAULT_KITTY_KEYS 0

#define HEADER_COLOR "\x1b[32m" /* Header */
#define CODE_COLOR   "\x1b[2m"  /* Code (hex, oct, dec) */
#define SYM_COLOR    "\x1b[36m" /* Symbol */
#define TRANS_COLOR  "\x1b[1m"  /* Translation */
#define RESET        "\x1b[0m"
