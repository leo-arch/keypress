# Keypress ⌨

### A raw keyboard input reader
---

<img src="https://i.postimg.cc/CMCph7cV/keypress.png" alt="Keypress" width="400" height="500">

### 1. Description

**Keypress** generates a byte-by-byte representation of keyboard inputs, whether for individual keys or key combinations. This representation includes the following formats: hexadecimal, octal, decimal, and the corresponding symbols.

Why? Have you ever developed a terminal program dealing with keyboard input? That is why.

Also, **keypress** is platform agonostic: it works on the TTY, X11, Wayland, and virtually any terminal emulator out there.

Awful, useful.

> [!TIP]
> Did you know that `printf "\xc3\x9f\n"` will print an `ß` (the german _Eszett_)?\
> Try with `printf "\xf0\x9f\x98\x80\n"`. Nice!

---

### 2. Installation

```sh
git clone https://github.com/leo-arch/keypress
cd keypress
make
sudo make install
```

---

### 3. Uninstallation

```sh
sudo make uninstall
```
