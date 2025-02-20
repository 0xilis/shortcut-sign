# shortcut-sign
 Open-Source Signed Shortcut CLI tool for Linux+macOS

Heavily WIP. Build by doing `make` after using git to init the submodules.

Note that GitHub actions *should* be automatically pushing to Release after build but it is not...

# Dependencies

- OpenSSL
- libplist 2.0

# CLI Usage
```
Usage: shortcut-sign command <options>

Commands:

 extract: extract unsigned shortcut from a signed shortcut.
 verify: verify signature of signed shortcut. (currently only contact-signed)
 auth: extract auth data of shortcut
 resign: resign a signed shortcut
 version: display version of shortcut-sign

Options:

 -i: path to the input file or directory.
 -o: path to the output file or directory.
 -u: optional option for resign command, for signing over shortcut with unsigned shortcut.
 -k: for signing/resigning, specify file containing ASN1 private ECDSA-P256 key
 -h: this ;-)

```

# Future Commands

- `sign`
