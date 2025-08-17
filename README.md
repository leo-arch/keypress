# Keypress ⌨

### A raw keyboard input reader
---

<img src="https://i.postimg.cc/CMCph7cV/keypress.png" alt="Keypress" width="400" height="500">

### 1. Description

#### 1.a. Interactive mode

By default, **keypress** runs in interactive mode. In this mode, it generates a byte-by-byte representation of keyboard inputs as the user types, whether for individual keys or key combinations. This representation includes the following formats: **hexadecimal**, **octal**, **decimal**, and the corresponding **symbols**.

Why? Have you ever developed a terminal program dealing with keyboard input? That is why.

Also, **keypress** is platform agonostic: it works on the TTY, X11, Wayland, and virtually any terminal emulator.

Awful, useful.

> [!TIP]
> Copy any text you like (yes, emojis are included) to the primary clipboard, and then paste it into the **keypress** interface to get the corresponding raw codes.
> 
> Did you know, for example, that `printf "\xc3\x9f\n"` will print an `ß` (the german _Eszett_)?\
> Try with `printf "\xf0\x9f\x98\x80\n"`. Nice!

#### 1.b. Translation mode

By using the `-t` option, **keypress** runs in translation mode: it translates a keyboard escape sequence passed as parameter into the corresponding symbolic/text representation. For example:

```sh
keypress -t "\x1b[1;7D"
```

This command will output `Ctrl+Alt+Left`.

> [!NOTE]
> For developers: The translation module can be used as an independent library. Simply include the `translate_key.h` header in your project (together with the corresponding source file) and use the `translate_key` function.
> Here's a quick example:
> ```c
> ...
> #include "translate_key.h"
> ...
> char str[] = "\x1b[1;7D";
> char *keysym = translate_key(str);
>
> if (keysym) {
>     printf("%s\n", keysym);
>     free(keysym);
> }
> ...
> ```

#### 1.c. The Kitty keyboard protocol

Use the `-k` option to enable support for the [Kitty keyboard protocol](https://sw.kovidgoyal.net/kitty/keyboard-protocol/). Version  0.2.3 or later required.

---

### 2. Installation

To install **keypress**, follow these steps:

```sh
git clone https://github.com/leo-arch/keypress
cd keypress
make
sudo make install
```

---

### 3. Uninstallation

To uninstall **keypress**, use the following command:

```sh
sudo make uninstall
```
