package org.webpki.androidcbordemo;

import android.content.Context;

import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDiagnosticNotationDecoder;
import org.webpki.cbor.CBORKeyPair;
import org.webpki.cbor.CBORObject;

import org.webpki.util.HexaDecimal;
import org.webpki.util.UTF8;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.KeyPair;

import java.security.cert.X509Certificate;

public class RawReader {

    static Context appContext;

    public static byte[] dataToBeEncrypted;

    public static String rsaKeyId;
    public static String ecKeyId;

    public static KeyPair rsaKeyPair;
    public static KeyPair ecKeyPair;

    public static X509Certificate[] ecCertPath;
    public static X509Certificate[] ed25519CertPath;

    public static byte[] secretKey;
    public static String secretKeyId;

    static byte[] getByteArrayFromInputStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
        byte[] buffer = new byte[10000];
        int bytes;
        while ((bytes = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytes);
        }
        is.close();
        return baos.toByteArray();
    }

    static byte[] getRawResource(int resource) throws Exception {
        return getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource));
    }

    static String getStringResource(int resource) throws Exception {
        return UTF8.decode(getRawResource(resource));
    }

    static CBORObject getCBORResource(int resource) throws Exception {
        return CBORDiagnosticNotationDecoder.decode(getStringResource(resource));
    }

    static String getCBORText(int resource) throws Exception {
        return CBORObject.decode(getRawResource(resource)).toString();
    }

    static KeyPair getKeyPair(int resource) throws Exception {
        return CBORKeyPair.convert(getCBORResource(resource));
    }

    RawReader(Context appContext) throws Exception {
        this.appContext = appContext;
        ecKeyId = "example.com:p256";
        ecKeyPair = getKeyPair(R.raw.ecprivatekey_cbor_txt);
        rsaKeyId = "example.com:r2048";
        rsaKeyPair = getKeyPair(R.raw.rsaprivatekey_cbor_txt);
        dataToBeEncrypted = getRawResource(R.raw.data2beencrypted_txt);
        ecCertPath = CBORCryptoUtils.decodeCertificateArray(
                getCBORResource(R.raw.ec_certpath_cbor_txt).getArray());
        ed25519CertPath = CBORCryptoUtils.decodeCertificateArray(
                getCBORResource(R.raw.ed25519_certpath_cbor_txt).getArray());
        secretKey = HexaDecimal.decode(getStringResource(R.raw.secretkey_hex));
        secretKeyId = getStringResource(R.raw.secret_key_id_txt);
    }
}
