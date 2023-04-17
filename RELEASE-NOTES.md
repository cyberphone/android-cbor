### Android CBOR - Relese Notes

Beyond 1.0.0:
- X25519 now works on Android 13.  Static ECDH may use <code>AndroidKeystore</code>. See
https://cyberphone.github.io/android-cbor/distribution/apidoc/org/webpki/crypto/EncryptionCore.html#setEcProvider(java.lang.String,java.lang.String)
for details.
