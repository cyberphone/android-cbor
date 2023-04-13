## CBOR for Android
This repository contains a CBOR AAR library and an Android test application.
The latter mainly tests the cryptographic functions of the CBOR library.

The CBOR library conforms to the API described in:
https://cyberphone.github.io/android-cbor/distribution/apidoc/index.html.
Note that Ed25519 only works on Android 13+ and that Ed25519 signatures
cannot be validted, only generated.  This is due to limitations in Android
and will presumably be fixed in Android 14.

The rest of the library is verified to work down to Android 7 (API 24).

### Usage
To use the precompiled module you only to copy the AAR
file locted in 
https://github.com/cyberphone/android-cbor/tree/main/distribution
to a ```libs``` folder in your application and then add the line
```code
implementation files('libs/org.webpki-jlibcbor-1.0.0.aar')
```
to the ```dependencies```section of the Gradle file.
 
 ### Source Code
The library source code is availble in:
https://github.com/cyberphone/android-cbor/tree/main/jlibcbor.

Although the library is fairly compact, most applications can eliminate files that do not apply.
For example if you don't use encryption, you can remove all files ending with Encrypter and Decrypter.
