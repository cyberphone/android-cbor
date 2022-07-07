package org.webpki.androidcbordemo;

import android.content.Context;

import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDiagnosticParser;
import org.webpki.cbor.CBORKeyPair;
import org.webpki.cbor.CBORObject;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;

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

    public static byte[] secretKey;
    public static String secretKeyId;

    static byte[] getRawResource(int resource) throws Exception {
        return ArrayUtil.getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource));
    }

    static String getStringResource(int resource) throws Exception {
        return new String(getRawResource(resource), "utf-8");
    }

    static CBORObject getCBORResource(int resource) throws Exception {
        return CBORDiagnosticParser.parse(getStringResource(resource));
    }

    static String getCBORText(int resource) throws Exception {
        return CBORObject.decode(getRawResource(resource)).toString();
    }

    static KeyPair getKeyPair(int resource) throws Exception {
        return CBORKeyPair.decode(getCBORResource(resource));
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
        secretKey = HexaDecimal.decode(getStringResource(R.raw.secretkey_hex));
        secretKeyId = getStringResource(R.raw.secret_key_id_txt);
    }
}
