package org.webpki.androidcbordemo;

import android.content.Context;
import android.os.Build;

import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORDiagnosticNotation;
import org.webpki.cbor.CBORKeyPair;
import org.webpki.cbor.CBORObject;

import org.webpki.util.HexaDecimal;
import org.webpki.util.IO;
import org.webpki.util.UTF8;

import java.security.KeyPair;

import java.security.cert.X509Certificate;

public class RawReader {

    static Context appContext;

    public static byte[] dataToBeEncrypted;

    public static String rsaKeyId;
    public static String ecKeyId;
    public static String ed25519KeyId;

    public static KeyPair rsaKeyPair;
    public static KeyPair ecKeyPair;
    public static KeyPair ed25519KeyPair;

    public static X509Certificate[] ecCertPath;
    public static X509Certificate[] ed25519CertPath;

    public static byte[] secretKey;
    public static String secretKeyId;

    static byte[] getRawResource(int resource) {
        return IO.getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource));
    }

    static String getStringResource(int resource) {
        return UTF8.decode(getRawResource(resource));
    }

    static CBORObject getCBORResource(int resource) {
        return CBORDiagnosticNotation.convert(getStringResource(resource));
    }

    static String getCBORText(int resource) {
        return CBORDecoder.decode(getRawResource(resource)).toString();
    }

    static KeyPair getKeyPair(int resource)  {
        return CBORKeyPair.convert(getCBORResource(resource));
    }

    RawReader(Context appContext) {
        this.appContext = appContext;
        ecKeyId = "example.com:p256";
        ecKeyPair = getKeyPair(R.raw.ecprivatekey_cbor_txt);
        rsaKeyId = "example.com:r2048";
        rsaKeyPair = getKeyPair(R.raw.rsaprivatekey_cbor_txt);
        ed25519KeyId = "example.com:ed25519";
        if (Build.VERSION.SDK_INT_FULL >= 3600001) {
            ed25519KeyPair = getKeyPair(R.raw.ed25519privatekey_cbor_txt);
        }
        dataToBeEncrypted = getRawResource(R.raw.data2beencrypted_txt);
        ecCertPath = CBORCryptoUtils.decodeCertificateArray(
                getCBORResource(R.raw.ec_certpath_cbor_txt).getArray());
        ed25519CertPath = CBORCryptoUtils.decodeCertificateArray(
                getCBORResource(R.raw.ed25519_certpath_cbor_txt).getArray());
        secretKey = HexaDecimal.decode(getStringResource(R.raw.secretkey_hex));
        secretKeyId = getStringResource(R.raw.secret_key_id_txt);
    }
}
