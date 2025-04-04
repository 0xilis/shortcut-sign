# shortcut-sign
 Open-Source Signed Shortcut CLI tool for Linux+macOS

Build by doing `make` after using git to init the submodules.

# Dependencies

- OpenSSL
- libplist 2.0

# CLI Usage
```
Usage: shortcut-sign command <options>

Commands:

 sign: sign an unsigned shortcut
 extract: extract unsigned shortcut from a signed shortcut
 verify: verify signature of signed shortcut
 auth: extract auth data of shortcut
 resign: resign a signed shortcut
 info: log info about signed shortcut's signing chain
 version: display version of shortcut-sign

Options:

 -i: path to the input file or directory
 -o: path to the output file or directory
 -u: optional option for resign command, for signing over shortcut with unsigned shortcut
 -k: for signing/resigning, specify file containing ASN1 private ECDSA-P256 key
 -a: for signing, specify file containing auth data
 -r/-raw_aar: flag to specify extracting the raw aar or sign raw aar data instead of plist
 -h: this ;-)

```

# Dumping Auth Data / Private Keys

[https://github.com/0xilis/appleid-key-dumper](https://github.com/0xilis/appleid-key-dumper) features a CLI for jailbreak iOS devices to dump the Apple ID keys and Auth Data from your device. If you want to dump them from an AMFI-disabled Mac, by modifying the hardcoded path in main.m as well as making a new Makefile, you can compile it and dump the keys.

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated. If you have contributions for a 2nd party library such as libshortcutsign or libNeoAppleArchive, please report them in their github pages. If you can't think of what to contribute, you can check the TODO section for a list. Please keep in mind that the goal of shortcut-sign is to provide a **cross-platform** signing tool, so things specific to macOS and not working on Linux are likely to not be accepted unless it is a need.

### Contributing (TODO):

- Write tests
- Build CLI for more devices
- Once libNeoAppleArchive neo_aea_sign_* functions are complete, utilize those rather than piggybacking off of embeddedSignedData
- Option to replicate identity services and fetch private key/cert/validation record over HTTPS from Apple ID, thus not requiring an Apple device to dump keys from. This is the most ambitious and will take the most time, and may not be done.
