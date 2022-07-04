package org.webpki.androidcbordemo;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

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
import org.webpki.cbor.CBORByteString;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSymKeyDecrypter;
import org.webpki.cbor.CBORTextString;
import org.webpki.cbor.CBORX509Signer;
import org.webpki.cbor.CBORX509Validator;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.util.ArrayUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class InstrumentedTest {
    static byte[] dataToEncrypt;

    @BeforeClass
    static public void initialize() throws Exception {
        new RawReader(InstrumentationRegistry.getInstrumentation().getTargetContext());
        dataToEncrypt = RawReader.getRawResource(R.raw.data2beencrypted_txt);
    }

    static String ANDROID_KEYSTORE = "AndroidKeyStore";

    static String KEY_1 = "key-1";
    static String KEY_2 = "key-2";

    static String SIGNATURE_LABEL = "signature";

    boolean useKeyId;
    int noPublicKey;
    void asymCoreEncryption(KeyPair keyPair,
                            KeyEncryptionAlgorithms kea,
                            ContentEncryptionAlgorithms cea) throws Exception{
        // Every other use keyId
        useKeyId = !useKeyId;
        boolean wantPublicKey = (noPublicKey++ % 3) != 0 && !useKeyId;
        CBORObject encrypted = new CBORAsymKeyEncrypter(keyPair.getPublic(), kea, cea)
                .setPublicKeyOption(wantPublicKey)
                .setKeyId(useKeyId ? new CBORTextString(KEY_1) : null)
                .encrypt(dataToEncrypt);
        // Simple decryption
        assertTrue("enc1",
                ArrayUtil.compare(dataToEncrypt,
                                  new CBORAsymKeyDecrypter(keyPair.getPrivate()).decrypt(encrypted)));
        Log.i("ENCRYPTION", encrypted.toString());
        // Sophisticated decryption
        assertTrue("enc2",
                ArrayUtil.compare(dataToEncrypt,
        new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject optionalKeyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm)
                    throws IOException, GeneralSecurityException {
                assertTrue("kea", kea == keyEncryptionAlgorithm);
                assertTrue("cea", cea == contentEncryptionAlgorithm);
                assertTrue("keyid", optionalKeyId == null ?
                        !useKeyId : useKeyId == true && optionalKeyId.getTextString().equals(KEY_1));
                assertTrue("pub", wantPublicKey ?
                        optionalPublicKey.equals(keyPair.getPublic()) : optionalPublicKey == null);
                return keyPair.getPrivate();
            }
        }).decrypt(encrypted)));
    }

    void encryptionTestVector(int resource,
                              String optionalKeyId,
                              PublicKey optionalPublicKey) throws Exception {
        assertTrue("Testv",
                ArrayUtil.compare(dataToEncrypt,
                  new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
                      @Override
                      public PrivateKey locate(PublicKey optionalPublicKey,
                                               CBORObject optionalKeyId,
                                               KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                               ContentEncryptionAlgorithms contentEncryptionAlgorithm)
                              throws IOException, GeneralSecurityException {
                          return RawReader.ecKeyPair.getPrivate();
                      }
                  }).decrypt(CBORObject.decode(RawReader.getRawResource(resource)))));
    }

    @Test
    public void encryption() throws Exception {
        for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
            for (ContentEncryptionAlgorithms cea : ContentEncryptionAlgorithms.values())
                asymCoreEncryption(kea.isRsa() ? RawReader.rsaKeyPair : RawReader.ecKeyPair, kea, cea);
        }
        encryptionTestVector(R.raw.ecdh_es_a128cbc_hs256_imp_cbor,
                null, null);
        encryptionTestVector(R.raw.ecdh_es_a192kw_a256cbc_hs512_pub_cbor,
                null, RawReader.ecKeyPair.getPublic());
        encryptionTestVector(R.raw.ecdh_es_a256kw_a256gcm_kid_cbor,
                "example.com:p256", null);

        assertTrue("Testv",
                ArrayUtil.compare(dataToEncrypt,
        new CBORSymKeyDecrypter(new CBORSymKeyDecrypter.KeyLocator() {
            @Override
            public byte[] locate(CBORObject optionalKeyId,
                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm)
                    throws IOException, GeneralSecurityException {
                assertTrue("kid",
                        optionalKeyId.getTextString().equals(RawReader.secretKeyId));
                return RawReader.secretKey;
            }
        }).decrypt(CBORObject.decode(
                RawReader.getRawResource(R.raw.a256_a128cbc_hs256_kid_cbor)))));
    }

    String getKeyObject(Object o) {
        return o.getClass().getCanonicalName() + "\n" + o.toString();
    }

    void printKeyPair(KeyPair keyPair) {
       Log.w("KPUB", getKeyObject(keyPair.getPublic()));
       Log.w("KPRI", getKeyObject(keyPair.getPrivate()));
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
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                .build());

        KeyPair keyPair = kpg.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        Log.i("CERT", keyStore.getCertificate(KEY_1).toString());

        printKeyPair(keyPair);
        printKeyPair(RawReader.rsaKeyPair);

        CBORObject signedData =
                new CBORAsymKeySigner(keyPair.getPrivate())
                        .setPublicKey(keyPair.getPublic())
                        .sign(SIGNATURE_LABEL, RawReader.getCBORResource(R.raw.cbor_data).getMap());
        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(SIGNATURE_LABEL, signedData);
        signedData =
                new CBORAsymKeySigner(keyPair.getPrivate(), AsymSignatureAlgorithms.RSAPSS_SHA512)
                        .sign(SIGNATURE_LABEL, RawReader.getCBORResource(R.raw.cbor_data).getMap());
        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(SIGNATURE_LABEL, signedData);
        byte[] signature =
        signedData.getMap().getObject(SIGNATURE_LABEL)
                .getMap().readByteStringAndRemoveKey(CBORCryptoConstants.SIGNATURE_LABEL);
        signature[5]++;
        try {
            signedData.getMap().getObject(SIGNATURE_LABEL)
                    .getMap().setObject(CBORCryptoConstants.SIGNATURE_LABEL,
                                        new CBORByteString(signature));
            new CBORAsymKeyValidator(keyPair.getPublic()).validate(SIGNATURE_LABEL, signedData);
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
                        .sign(SIGNATURE_LABEL, RawReader.getCBORResource(R.raw.cbor_data).getMap());
        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(SIGNATURE_LABEL, signedData);
        signedData =
                new CBORAsymKeySigner(keyPair.getPrivate())
                        .sign(SIGNATURE_LABEL, RawReader.getCBORResource(R.raw.cbor_data).getMap());
        Log.i("SIGN", signedData.toString());
        new CBORAsymKeyValidator(keyPair.getPublic()).validate(SIGNATURE_LABEL, signedData);

        keyStore.setEntry(
                KEY_2,
                new KeyStore.PrivateKeyEntry(RawReader.ecKeyPair.getPrivate(), RawReader.ecCertPath),
                new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .build());
        signedData =
                new CBORX509Signer(keyPair.getPrivate(), RawReader.ecCertPath)
                        .sign(SIGNATURE_LABEL, RawReader.getCBORResource(R.raw.cbor_data).getMap());
        Log.i("CERTSIGN", signedData.toString());
        new CBORX509Validator(new CBORX509Validator.Parameters() {
            @Override
            public void verify(X509Certificate[] certificatePath,
                               AsymSignatureAlgorithms algorithm)
                    throws IOException, GeneralSecurityException {
                if (algorithm != KeyAlgorithms.P_256.getRecommendedSignatureAlgorithm()) {
                    throw new GeneralSecurityException("alg");
                }
                int q = 0;
                for (X509Certificate cert : RawReader.ecCertPath) {
                    if (!certificatePath[q++].equals(cert)) {
                        throw new GeneralSecurityException("cert");
                    }
                }
            }
        }).validate(SIGNATURE_LABEL, signedData);
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
}