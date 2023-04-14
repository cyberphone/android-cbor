## CBOR for Android
This repository contains a CBOR AAR library and an Android application.
The latter is only intended for testing and demonstrating the cryptographic functions of the CBOR library.

The CBOR library conforms to the API described in:
https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/cbor/package-summary.html.
Note that Ed25519 only works on Android 13+ and that Ed25519 signatures
cannot be validated, only generated.  This is due to limitations in Android
and will presumably be fixed in Android 14.

The rest of the library has been verified to work from Android 7 (API 24) and up.

### Usage
To use the precompiled module, copy the AAR file located in 
https://github.com/cyberphone/android-cbor/tree/main/distribution
to a ```libs``` folder in the application and then add the line
```code
implementation files('libs/org.webpki-jlibcbor-1.0.0.aar')
```
to the ```dependencies``` section of the Gradle file.
 
### Source Code
The library source code is available in:
https://github.com/cyberphone/android-cbor/tree/main/jlibcbor.
