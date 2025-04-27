package org.webpki.androidcbordemo;

import android.os.Build;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

import android.util.Base64;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORBytes;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORDiagnosticNotation;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORKeyPair;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORSymKeyDecrypter;
import org.webpki.cbor.CBORValidator;
import org.webpki.cbor.CBORX509Signer;
import org.webpki.cbor.CBORX509Validator;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.KeyTypes;
import org.webpki.crypto.OkpSupport;

import org.webpki.util.HexaDecimal;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;
import static org.webpki.cbor.CBORCryptoConstants.CSF_CONTAINER_LBL;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class InstrumentedTest {
    static byte[] DATA_TO_ENCRYPT;

    @BeforeClass
    static public void initialize() {
        new RawReader(InstrumentationRegistry.getInstrumentation().getTargetContext());
        DATA_TO_ENCRYPT = RawReader.getRawResource(R.raw.data2beencrypted_txt);
    }

    static String ANDROID_KEYSTORE = "AndroidKeyStore";

    static String KEY_1 = "key-1";
    static String KEY_2 = "key-2";

    boolean useKeyId;
    int noPublicKey;
    void asymCoreEncryption(KeyPair keyPair,
                            KeyEncryptionAlgorithms kea,
                            ContentEncryptionAlgorithms cea) {
        // Every other use keyId
        useKeyId = !useKeyId;
        boolean wantPublicKey = (noPublicKey++ % 3) != 0 && !useKeyId;
        CBORObject encrypted = new CBORAsymKeyEncrypter(keyPair.getPublic(), kea, cea)
                .setKeyId(useKeyId ? new CBORString(KEY_1) : null)
                .setPublicKeyOption(wantPublicKey)
                .encrypt(DATA_TO_ENCRYPT);
        // Simple decryption
        assertTrue("enc1",
                Arrays.equals(DATA_TO_ENCRYPT,
                              new CBORAsymKeyDecrypter(keyPair.getPrivate()).decrypt(encrypted)));
        Log.i("ENCRYPTION", encrypted.toString());
        // Sophisticated decryption
        assertTrue("enc2",
                Arrays.equals(
            new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {

                @Override
                public PrivateKey locate(PublicKey optionalPublicKey,
                                         CBORObject optionalKeyId,
                                         KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                         ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                    assertTrue("kea", kea == keyEncryptionAlgorithm);
                    assertTrue("cea", cea == contentEncryptionAlgorithm);
                    assertTrue("keyid", optionalKeyId == null ?
                            !useKeyId : useKeyId == true && optionalKeyId.getString().equals(KEY_1));
                    assertTrue("pub", wantPublicKey ?
                            optionalPublicKey.equals(keyPair.getPublic()) : optionalPublicKey == null);
                    return keyPair.getPrivate();
                }

            }).decrypt(encrypted), DATA_TO_ENCRYPT));
        /*
        new CBORAsymKeyDecrypter((optionalPublicKey,
                                  optionalKeyId,
                                  keyEncryptionAlgorithm,
                                  contentEncryptionAlgorithm) -> {
            assertTrue("kea", kea == keyEncryptionAlgorithm);
            assertTrue("cea", cea == contentEncryptionAlgorithm);
            assertTrue("keyid", optionalKeyId == null ?
                    !useKeyId : useKeyId == true && optionalKeyId.getString().equals(KEY_1));
            assertTrue("pub", wantPublicKey ?
                    optionalPublicKey.equals(keyPair.getPublic()) : optionalPublicKey == null);
            return keyPair.getPrivate();
        }).decrypt(encrypted)));

         */
    }

    void signatureTestVector(int resource, CBORValidator<?> validator) {
        CBORMap signedObject = CBORDecoder.decode(RawReader.getRawResource(resource)).getMap();
        validator.validate(signedObject);
    }

    @Test
    public void certPublicKey() {
        Log.i("Ed25519", RawReader.ed25519CertPath[0].getPublicKey().toString());
        Log.i("EC", RawReader.ecCertPath[0].getPublicKey().toString());
    }

    @Test
    public void openSSLPublicKey() throws Exception {
        KeyFactory.getInstance("Ed25519").generatePublic(
                new X509EncodedKeySpec(new byte[]
            {(byte)0x30, (byte)0x2a, (byte)0x30, (byte)0x05,
             (byte)0x06, (byte)0x03, (byte)0x2b, (byte)0x65,
             (byte)0x70, (byte)0x03, (byte)0x21, (byte)0x00,
             (byte)0xec, (byte)0x44, (byte)0xfe, (byte)0xf2,
             (byte)0x44, (byte)0x2a, (byte)0x1a, (byte)0x4c,
             (byte)0x75, (byte)0xed, (byte)0x1a, (byte)0x07,
             (byte)0x55, (byte)0x12, (byte)0x27, (byte)0xe0,
             (byte)0x5f, (byte)0x0b, (byte)0x5e, (byte)0xfc,
             (byte)0x1e, (byte)0xfd, (byte)0xe8, (byte)0xb0,
             (byte)0x6f, (byte)0xc2, (byte)0xc4, (byte)0xaf,
             (byte)0x1f, (byte)0x95, (byte)0xf5, (byte)0xe4}
        ));
    }

    @Test
    public void signatures() {
        signatureTestVector(R.raw.a256_hs256_kid_cbor,
                            new CBORHmacValidator(RawReader.secretKey));
        signatureTestVector(R.raw.p256_esp256_imp_cbor,
                new CBORAsymKeyValidator(RawReader.ecKeyPair.getPublic()));
        signatureTestVector(R.raw.p256_esp256_imp_cbor,
                new CBORAsymKeyValidator((optionalPublicKey, optionalKeyId, algorithm) -> {
                    assertTrue("imp",
                            optionalKeyId == null && optionalPublicKey == null);
                    return RawReader.ecKeyPair.getPublic();
                }));
        signatureTestVector(R.raw.p256_esp256_kid_cbor,
                new CBORAsymKeyValidator((optionalPublicKey, optionalKeyId, algorithm) -> {
                    assertTrue("kid",
                            RawReader.ecKeyId.equals(optionalKeyId.getString()) &&
                                    optionalPublicKey == null);
                    return RawReader.ecKeyPair.getPublic();
                }));
        signatureTestVector(R.raw.p256_esp256_pub_cbor,
                new CBORAsymKeyValidator((optionalPublicKey, optionalKeyId, algorithm) -> {
                    assertTrue("kid",
                            optionalKeyId == null &&
                                    RawReader.ecKeyPair.getPublic().equals(optionalPublicKey));
                    return RawReader.ecKeyPair.getPublic();
                }));

        signatureTestVector(R.raw.r2048_rs256_cer_cbor,
                new CBORX509Validator((certificatePath, algorithm) ->
                        assertTrue("cert", certificatePath[0].getPublicKey().equals(
                                RawReader.rsaKeyPair.getPublic()))));
/*
        signatureTestVector(R.raw.ed25519_ed25519_pub_cbor,
                new CBORAsymKeyValidator((optionalPublicKey, optionalKeyId, algorithm) -> {
                    assertTrue("kid",
                            optionalKeyId == null);
                    return optionalPublicKey;
                }));
*/
//        Log.i("X.509", RawReader.ed25519CertPath[0].toString());
    }

    void encryptionTestVector(int resource,
                              String keyId,
                              PublicKey publicKey) {
        CBORObject encryptionObject = CBORDecoder.decode(RawReader.getRawResource(resource));
        CBORMap cefContainer = MainActivity.unwrapOptionalTag(encryptionObject);
        PrivateKey privateKey = cefContainer
                .get(CBORCryptoConstants.CEF_KEY_ENCRYPTION_LBL)
                     .getMap().containsKey(CBORCryptoConstants.CEF_EPHEMERAL_KEY_LBL) ?
                RawReader.ecKeyPair.getPrivate() : RawReader.rsaKeyPair.getPrivate();
        assertTrue("Testv",
                   Arrays.equals(DATA_TO_ENCRYPT,
                           new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
               @Override
               public PrivateKey locate(PublicKey optionalPublicKey,
                                        CBORObject optionalKeyId,
                                        KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                        ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                   assertTrue("PUB",
                          (publicKey == null && optionalPublicKey == null) ||
                                  (publicKey != null && publicKey.equals(optionalPublicKey)));
                   assertTrue("KID", (keyId == null && optionalKeyId == null) ||
                          (keyId != null && keyId.equals(optionalKeyId.getString())));
                    return privateKey;
                }
                      /*
                      assertTrue("PUB",
                              (publicKey == null && optionalPublicKey == null) ||
                                      (publicKey != null && publicKey.equals(optionalPublicKey)));
                      assertTrue("KID", (keyId == null && optionalKeyId == null) ||
                              (keyId != null && keyId.equals(optionalKeyId.getString())));
                      return privateKey;

                       */
                  }).setTagPolicy(CBORCryptoUtils.POLICY.OPTIONAL, null).decrypt(encryptionObject)));
        byte[] tag = cefContainer.remove(CBORCryptoConstants.CEF_TAG_LBL).getBytes();
        cefContainer.set(CBORCryptoConstants.CEF_TAG_LBL, new CBORBytes(tag));
        new CBORAsymKeyDecrypter(privateKey)
                .setTagPolicy(CBORCryptoUtils.POLICY.OPTIONAL, null)
                .decrypt(encryptionObject);

        tag = cefContainer.remove(CBORCryptoConstants.CEF_TAG_LBL).getBytes();
        tag[5]++;
        cefContainer.set(CBORCryptoConstants.CEF_TAG_LBL, new CBORBytes(tag));
        try {
            new CBORAsymKeyDecrypter(privateKey)
                    .setTagPolicy(CBORCryptoUtils.POLICY.OPTIONAL, null)
                    .decrypt(encryptionObject);
            fail("never");
        } catch (Exception e) {

        }
    }

    @Test
    public void encryption() {
        for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
            for (ContentEncryptionAlgorithms cea : ContentEncryptionAlgorithms.values()) {
                asymCoreEncryption(kea.isRsa() ? RawReader.rsaKeyPair : RawReader.ecKeyPair, kea, cea);
            }
        }
        encryptionTestVector(R.raw.ecdh_es_a128cbc_hs256_imp_cbor,
                null, null);
        encryptionTestVector(R.raw.ecdh_es_a192kw_a256cbc_hs512_pub_cbor,
                null, RawReader.ecKeyPair.getPublic());
        encryptionTestVector(R.raw.p256_ecdh_es_a256kw_a256gcm_tag2dim_pub_cbor,
                null, RawReader.ecKeyPair.getPublic());
        encryptionTestVector(R.raw.ecdh_es_a256kw_a256gcm_kid_cbor,
                RawReader.ecKeyId, null);
        encryptionTestVector(R.raw.r2048_rsa_oaep_256_a256gcm_kid_cbor,
                RawReader.rsaKeyId, null);
        encryptionTestVector(R.raw.r2048_rsa_oaep_a256cbc_hs512_kid_cbor,
                RawReader.rsaKeyId, null);

        assertTrue("Testv",
                Arrays.equals(DATA_TO_ENCRYPT,
        new CBORSymKeyDecrypter((optionalKeyId, contentEncryptionAlgorithm) -> {
            assertTrue("kid",
                    optionalKeyId.getString().equals(RawReader.secretKeyId));
            return RawReader.secretKey;
        }).decrypt(CBORDecoder.decode(
                RawReader.getRawResource(R.raw.a256_a128cbc_hs256_kid_cbor)))));
    }

    String getKeyObject(Object o) {
        return o.getClass().getCanonicalName() + "\n" + o.toString();
    }

    void printKeyPair(KeyPair keyPair) {
       Log.w("KPUB", getKeyObject(keyPair.getPublic()));
       Log.w("KPRI", getKeyObject(keyPair.getPrivate()));
    }

    KeyPair generateKeyPair(boolean androidKs,
                            KeyAlgorithms keyAlgorithm) throws Exception {
        KeyPairGenerator kpg;
        if (androidKs) {
            if (keyAlgorithm.getKeyType() == KeyTypes.RSA) {
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
                                                   ANDROID_KEYSTORE);
                kpg.initialize(new KeyGenParameterSpec.Builder(
                    KEY_2,
                    KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(
                            keyAlgorithm.getPublicKeySizeInBits(), RSAKeyGenParameterSpec.F4))
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
                                           KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                    .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                    .build());
            } else {
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,
                                                                 ANDROID_KEYSTORE);
                kpg.initialize(new KeyGenParameterSpec.Builder(
                    KEY_2,
                    KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec(keyAlgorithm.getJceName()))
                    .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                    .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                    .build());
            }
        } else {
            if (keyAlgorithm.getKeyType() == KeyTypes.RSA) {
                AlgorithmParameterSpec paramSpec = new RSAKeyGenParameterSpec(
                        keyAlgorithm.getPublicKeySizeInBits(), RSAKeyGenParameterSpec.F4);
                kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(paramSpec, new SecureRandom());
            } else if (keyAlgorithm.getKeyType() == KeyTypes.EC) {
                AlgorithmParameterSpec paramSpec =
                        new ECGenParameterSpec(keyAlgorithm.getJceName());
                kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(paramSpec, new SecureRandom());
            } else {
                kpg = KeyPairGenerator.getInstance("XDH");
                kpg.initialize(NamedParameterSpec.X25519, new SecureRandom());
            }
        }
        KeyPair keyPair = kpg.generateKeyPair();
//        Log.i("ECDHK", keyPair.getPrivate().toString());
        return keyPair;
    }
    private void oneShot(KeyAlgorithms ka,
                         KeyEncryptionAlgorithms kea,
                         ContentEncryptionAlgorithms cea,
                         String staticProvider) throws Exception {
        KeyPair keyPair = generateKeyPair(staticProvider != null, ka);
        if (ka.getKeyType() != KeyTypes.RSA) {
          // Apparently the private key information takes you to the proper provider
          //  EncryptionCore.setEcProvider(staticProvider, ephemeralProvider);
        }
        byte[] encrypted = new CBORAsymKeyEncrypter(keyPair.getPublic(), kea, cea)
                .encrypt(DATA_TO_ENCRYPT).encode();
        assertTrue("Enc", Arrays.equals(DATA_TO_ENCRYPT,
                new CBORAsymKeyDecrypter(keyPair.getPrivate())
                        .decrypt(CBORDecoder.decode(encrypted))));
        encrypted = new CBORAsymKeyEncrypter(keyPair.getPublic(), kea, cea)
                .setPublicKeyOption(true)
                .encrypt(DATA_TO_ENCRYPT).encode();
        assertTrue("Enc2", Arrays.equals(DATA_TO_ENCRYPT,
                new CBORAsymKeyDecrypter(keyPair.getPrivate())
                        .decrypt(CBORDecoder.decode(encrypted))));
 //       EncryptionCore.setEcProvider(null, null);
 //       EncryptionCore.setRsaProvider(null);
    }

    private void providerShot(KeyAlgorithms ka,
                              KeyEncryptionAlgorithms kea,
                              ContentEncryptionAlgorithms cea) throws Exception {
        // Using the default provider
        oneShot(ka, kea, cea, null);

        if (Build.VERSION.SDK_INT >= 33) {
            // Protected client keys
            oneShot(ka, kea, cea, ANDROID_KEYSTORE);
        }
    }

    @Test
    public void androidKeystore() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_1,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048,RSAKeyGenParameterSpec.F4))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS,
                                      KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                .build());

        KeyPair keyPair = kpg.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

//        Log.i("CERT", keyStore.getCertificate(KEY_1).toString());

        printKeyPair(keyPair);
        printKeyPair(RawReader.rsaKeyPair);

        CBORObject signedData =
                new CBORAsymKeySigner(keyPair.getPrivate())
                        .setPublicKey(keyPair.getPublic())
                        .sign(RawReader.getCBORResource(R.raw.somedata_cbor_txt).getMap());
        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(signedData);
        signedData =
                new CBORAsymKeySigner(keyPair.getPrivate(), AsymSignatureAlgorithms.RSAPSS_SHA512)
                        .sign(RawReader.getCBORResource(R.raw.somedata_cbor_txt).getMap());
        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(signedData);
        byte[] signature =
        signedData.getMap().get(CSF_CONTAINER_LBL)
                .getMap().remove(CBORCryptoConstants.CSF_SIGNATURE_LBL).getBytes();
        signature[5]++;
        try {
            signedData.getMap().get(CSF_CONTAINER_LBL)
                    .getMap().set(CBORCryptoConstants.CSF_SIGNATURE_LBL,
                                        new CBORBytes(signature));
            new CBORAsymKeyValidator(keyPair.getPublic()).validate(signedData);
            fail("must not");
        } catch (Exception e) { }

        kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);

        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_2,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                .build());

        keyPair = kpg.generateKeyPair();

        printKeyPair(keyPair);
        printKeyPair(RawReader.ecKeyPair);

        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        Log.i("CERT", keyStore.getCertificate(KEY_2).toString());
        signedData =
                new CBORAsymKeySigner(keyPair.getPrivate())
                        .setPublicKey(keyPair.getPublic())
                        .sign(RawReader.getCBORResource(R.raw.somedata_cbor_txt).getMap());
//        Log.i("SIGN", signedData.toString());

        new CBORAsymKeyValidator(keyPair.getPublic()).validate(signedData);
        signedData =
                new CBORAsymKeySigner(keyPair.getPrivate())
                        .sign(RawReader.getCBORResource(R.raw.somedata_cbor_txt).getMap());
//        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(signedData);

        keyStore.setEntry(
                KEY_2,
                new KeyStore.PrivateKeyEntry(RawReader.ecKeyPair.getPrivate(),
                        RawReader.ecCertPath),
                new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .build());

        signedData =
                new CBORX509Signer(((KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_2, null)).getPrivateKey(), RawReader.ecCertPath)
                        .sign(RawReader.getCBORResource(R.raw.somedata_cbor_txt).getMap());
//        Log.i("CERTSIGN", signedData.toString());

        new CBORX509Validator((certificatePath, algorithm) -> {
            if (algorithm != KeyAlgorithms.P_256.getRecommendedSignatureAlgorithm()) {
                throw new CryptoException("alg");
            }
            int q = 0;
            for (X509Certificate cert : RawReader.ecCertPath) {
                if (!certificatePath[q++].equals(cert)) {
                    throw new CryptoException("cert");
                }
            }
        }).validate(signedData);

        if (Build.VERSION.SDK_INT >= 33) {
            kpg = KeyPairGenerator.getInstance("EC", ANDROID_KEYSTORE);
            final String alias = "ed25519-alias";
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("ed25519"))
                    .setDigests(KeyProperties.DIGEST_NONE).build();
            kpg.initialize(keySpec);
            keyPair = kpg.generateKeyPair();
            signedData =
                new CBORAsymKeySigner(keyPair.getPrivate())
                        .setPublicKey(keyPair.getPublic())
                        .sign(RawReader.getCBORResource(R.raw.somedata_cbor_txt).getMap());
            Log.i("ED25", signedData.toString());
            Log.i("ED25", KeyAlgorithms.getKeyAlgorithm(keyPair.getPublic()).toString());
            Log.i("ED25", "L=" +OkpSupport.public2RawKey(keyPair.getPublic(),
                                                         KeyAlgorithms.getKeyAlgorithm(
                                                                 keyPair.getPublic())).length);
            Log.i("ED25", "PK=" + keyPair.getPublic().getClass().getCanonicalName());

/*          As of 2023-01-30 there is no validation support in Android :(
            new CBORAsymKeyValidator(keyPair.getPublic()).validate(SIGNATURE_LABEL, signedData);

 */
        }

        // Encryption with ECDH
        providerShot(KeyAlgorithms.P_256,
                     KeyEncryptionAlgorithms.ECDH_ES,
                     ContentEncryptionAlgorithms.A256GCM);

        KeyPair kp = generateKeyPair(true, KeyAlgorithms.RSA2048);
        Cipher cp = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cp.init(Cipher.DECRYPT_MODE, kp.getPrivate(), new OAEPParameterSpec("SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT));

        generateKeyPair(false, KeyAlgorithms.RSA2048);

        // Encryption with RSA
        providerShot(KeyAlgorithms.RSA2048,
                     KeyEncryptionAlgorithms.RSA_OAEP,
                     ContentEncryptionAlgorithms.A256GCM);
        providerShot(KeyAlgorithms.RSA2048,
                KeyEncryptionAlgorithms.RSA_OAEP,
                ContentEncryptionAlgorithms.A256GCM);
        if (Build.VERSION.SDK_INT >= 33) {
            generateKeyPair(true, KeyAlgorithms.X25519);
       //     generateKeyPair(false, KeyAlgorithms.X25519);
            providerShot(KeyAlgorithms.X25519,
                         KeyEncryptionAlgorithms.ECDH_ES,
                         ContentEncryptionAlgorithms.A256GCM);
        }
    }

    @Test
    public void attestationPlay() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_1, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAttestationChallenge("hello world".getBytes("utf-8"))
                .build());

        KeyPair keyPair = kpg.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        for (Certificate certificate : keyStore.getCertificateChain(KEY_1)) {
            Log.i("ATT", certificate.toString());
        }
    }

    @Test
    public void useAppContext() {
        assertEquals("org.webpki.androidcbordemo", RawReader.appContext.getPackageName());
    }

    void utf8DecoderTest(String hex, boolean ok) {
        byte[] cbor = HexaDecimal.decode(hex);
        try {
            byte[] roundTrip = CBORDecoder.decode(cbor).encode();
            assertTrue("OK", ok);
            assertTrue("Conv", Arrays.equals(cbor, roundTrip));
        } catch (Exception e) {
            assertFalse("No good", ok);
        }
    }

    void utf8EncoderTest(String string, boolean ok) {
         try {
            String encodedString = CBORDiagnosticNotation.convert(
                    "\"" + string + "\"").getString();
            assertTrue("OK", ok);
            assertTrue("Conv", string.equals(encodedString));
            byte[] encodedBytes = CBORDiagnosticNotation.convert(
                    "'" + string + "'").getBytes();
            assertTrue("OK", ok);
            assertTrue("Conv2", Arrays.equals(encodedBytes, string.getBytes("utf-8")));
        } catch (Exception e) {
            assertFalse("No good", ok);
        }
    }

    @Test
    public void utf8Test() {
        utf8DecoderTest("62c328", false);
        utf8DecoderTest("64f0288cbc", false);
        utf8DecoderTest("64f0908cbc", true);
        utf8EncoderTest("\uD83D", false);
        utf8EncoderTest("\uD83D\uDE2D", true);
    }

    @Test
    public void succeededED25519PrivateKey() {
        // In API 33? Nope.
        OkpSupport.raw2PrivateKey(
            HexaDecimal.decode("fe49acf5b92b6e923594f2e83368f680ac924be93cf533aecaf802e37757f8c9"),
            KeyAlgorithms.ED25519);
    }

    @Test
    public void succeededED25519KeyPair() {
        // In API 33? Nope.
        CBORKeyPair.convert(CBORDecoder.decode(HexaDecimal.decode(
            "a401012006215820fe49acf5b92b6e923594f2e83368f680" +
             "ac924be93cf533aecaf802e37757f8c9235820d1f96bfba" +
             "6d7b38e7d7fdab002adb466cdcd8b34c62041f9feb4c3168ba6155e")));
    }

    @Test
    public void succeededED25519PublicKey() {
        // In API 33? Nope.
        CBORPublicKey.convert(CBORDecoder.decode(HexaDecimal.decode(
            "a301012006215820fe49acf5b92b6e923594f2e83368f680ac924be93cf533aecaf802e37757f8c9")));
    }

    @Test
    public void succeededX25519KeyPair() {
        CBORKeyPair.convert(CBORDecoder.decode(HexaDecimal.decode(
                "a401012004215820e99a0cef205894960d9b1c05978513dcc" +
                "b42a13bfbced523a51b8a117ad5f00c2358207317e5f3a115" +
                "99caab474ee65843427f517fe4d8b99add55886c84441e90d6f0")));
    }

    @Test
    public void succeededX25519PublicKey() {
        CBORPublicKey.convert(CBORDecoder.decode(HexaDecimal.decode(
            "a301012004215820e99a0cef205894960d9b1c05978513dccb42a13bfbced523a51b8a117ad5f00c")));
    }

    @Test
    public void succeededRsaOaep256AndroidKeystore() throws Exception {
        KeyPair keyPair = generateKeyPair(true, KeyAlgorithms.RSA2048);
        assertTrue("OAEP-256", Arrays.equals(DATA_TO_ENCRYPT,
            new CBORAsymKeyDecrypter(keyPair.getPrivate()).decrypt(
                new CBORAsymKeyEncrypter(keyPair.getPublic(),
                                         KeyEncryptionAlgorithms.RSA_OAEP_256,
                                         ContentEncryptionAlgorithms.A256GCM)
                                            .encrypt(DATA_TO_ENCRYPT))));
    }
}