# CBOR for Android
This repository contains a CBOR library in Java and an Android test application.
The latter mainly tests the cryptographic functions of the CBOR library.

The CBOR library conforms to the API described in https://cyberphone.github.io/javaapi/org/webpki/cbor/package-summary.html 
except for EdDSA and XDH support which is currently not a part of the Android platform.

Although the library is fairly compact, most applications can eliminate files that do not apply.
For example if you don't use encryption, you can remove all files ending with Encrypter and Decrypter.
 
