# shortcut-sign
 Open-Source Signed Shortcut CLI tool for Linux+macOS

Heavily WIP. Build by doing `make` after using git to init the submodules.

Note that GitHub actions *should* be automatically pushing to Release after build but it is not...

# CLI Usage
```
Usage: shortcut-sign command <options>

Commands:

 extract: extract unsigned shortcut from a signed shortcut.
 auth: extract auth data of shortcut
 version: display version of shortcut-sign

Options:

 -i: path to the input file or directory.
 -o: path to the output file or directory.
 -h: this ;-)

```

# Future Commands

- `sign`
- `verify`
- `resign`
