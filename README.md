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

 sign: sign an unsigned shortcut.
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
 -a: for signing, specify file containing auth data
 -h: this ;-)

```

Note that this is in beta and some commands are pretty buggy. That being said, all commands are functional to some degree.

# Dumping Auth Data / Private Keys

1. Without disabling AMFI

For some reason, you can hook Shortcuts in the simulator to dump the auth data and private keys without needing to disable AMFI.

Use [QMCDumper-Simulator](https://github.com/0xilis/QMCDumper-Simulator) to dump a qmc/qmd file. Your auth data and private key are stored in data.qmd by:

| Offset | Size | Description |
| --- | --- | --- |
| 0x0 | 4 | QMD magic (always "QMD" followed by a null byte) |
| 0x4 | 4 | privateKeyLen (length of private key) |
| 0x8 | privateKeyLen | Private ECDSA-P256 key |
| 0x8+privateKeyLen | auth_data_size | Auth Data |

After hooking simulator with QMCDumper-Simulator, try and make Shortcuts call the Apple ID signing function within simulator.

2. Disabling AMFI

Here is example code of generating the private key and auth data:

```objc
//Initialize the SFAppleIDAccount (Sharing.framework)
SFAppleIDAccount *account = [[[SFAppleIDClient alloc]init]myAccountWithError:&err];
//Get the SFAppleIDIdentity from it
SFAppleIDIdentity *identity = [account identity];
// Get the certificates from that identity
OpaqueSecCertificateRef cert = [[account identity]copyCertificate];
OpaqueSecCertificateRef intercert = [[account identity]copyIntermediateCertificate];
// Get private key from Apple ID. This will be used to sign a public key that we will randomly generate.
OpaqueSecKeyRef privateKey = [identity copyPrivateKey];
// Generate an ECDSA-P256 key
NSMutableDictionary *mutableDict = [NSMutableDictionary dictionary];
mutableDict[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeECSECPrimeRandom;
mutableDict[(__bridge id)kSecAttrKeySizeInBits] = @256;
mutableDict[(__bridge id)kSecAttrIsPermanent] = @NO;
SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)mutableDict, 0);
// Get public key
SecKeyRef pubKey = SecKeyCopyPublicKey(key);
// Sign it with the Apple ID private key
CFDataRef data = SecKeyCopyExternalRepresentation(pubKey);
NSData *signature = (__bridge NSData *)SecKeyCreateSignature(privateKey, kSecKeyAlgorithmRSASignatureMessagePSSSHA256, data, 0);
// Generate auth data
dict = [NSMutableDictionary dictionaryWithDictionary:@{
                @"AppleIDCertificateChain" : @{
(__bridge NSData*)SecCertificateCopyData(cert),
(__bridge NSData*)SecCertificateCopyData(intercert),
 },
                @"SigningPublicKey" : pubKey,
                @"SigningPublicKeySignature" : signature,
                @"AppleIDValidationRecord" : [account validationRecord],
            }];
```

Write functions to write dict and key variables to a file so you can have them dumped. Then, sign your binary with this entitlement plist:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>keychain-access-groups</key>
	<array>
		<string>com.apple.sharing.appleidauthentication</string>
	</array>
</dict>
</plist>
```

# Contributing

Contributions are welcome! Not just to the code, but also better documentation would also be appreciated. If you have contributions for a 2nd party library such as libshortcutsign or libNeoAppleArchive, please report them in their github pages. If you can't think of what to contribute, you can check the TODO section for a list. Please keep in mind that the goal of shortcut-sign is to provide a **cross-platform** signing tool, so things specific to macOS and not working on Linux are likely to not be accepted unless it is a need.

### Contributing (TODO):

- Write tests
- Write a private key and auth data extractor for jailbroken iOS devices
- Build CLI for more devices
- Once libNeoAppleArchive neo_aea_sign_* functions are complete, utilize those rather than piggybacking off of embeddedSignedData
- Option to replicate identity services and fetch private key/cert/validation record over HTTPS from Apple ID, thus not requiring an Apple device to dump keys from. This is the most ambitious and will take the most time, and may not be done.
