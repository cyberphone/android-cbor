## CBOR for Android
This repository contains a CBOR AAR library and an Android application.
The latter is only intended for testing and demonstrating the cryptographic functions of the CBOR library.

<table><tr><td>Note that this document as well as the on-line API reference, mirror the "trunk".
 Releases come with release specific information which may differ considerably between versions.</td></tr></table>

### Core Features
- [Deterministic encoding](https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/package-summary.html#deterministic-encoding) support
- [Diagnostic notation](https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/package-summary.html#diagnostic-notation) support including decoder
- [Enveloped signature](https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/doc-files/signatures.html) support
- [Encryption](https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/doc-files/encryption.html) support
- [checkForUnread()](https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/CBORObject.html#checkForUnread()) for catching possible misunderstandings regarding protocol contracts
- [URL-based object Id tag](https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/doc-files/typed-objects.html)

The CBOR library API is described in:
https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/package-summary.html.
Note that Ed25519 only works on Android 13+ and that Ed25519 signatures
cannot be validated, only generated.  This is due to limitations in Android
and will presumably be fixed in Android 14.

The rest of the library has been verified to work from Android 7 (API 24) and up.

### Usage in Applications
To use the precompiled module, copy the AAR file located in 
https://github.com/cyberphone/android-cbor/tree/main/distribution
to a ```libs``` folder in the application and then add the line
```code
implementation files('libs/org.webpki-jlibcbor-1.0.3.aar')
```
to the ```dependencies``` section of the Gradle file.

### Source Code
The library source code is available in:
https://github.com/cyberphone/android-cbor/tree/main/jlibcbor.

### CBOR Playground
A feature-wise identical implementation can be tested on-line at:
https://test.webpki.org/csf-lab/home.

### Updates
See https://github.com/cyberphone/android-cbor/tree/main/RELEASE-NOTES.txt.

Version 1.0.3, 2023-05-06
