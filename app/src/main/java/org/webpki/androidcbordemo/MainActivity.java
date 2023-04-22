/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.androidcbordemo;

import android.os.Bundle;

import android.util.Log;

import android.webkit.JavascriptInterface;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebResourceRequest;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import androidx.webkit.WebViewAssetLoader;

import androidx.appcompat.app.AppCompatActivity;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORBigInteger;
import org.webpki.cbor.CBORBoolean;
import org.webpki.cbor.CBORBytes;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecrypter;
import org.webpki.cbor.CBORDiagnosticNotationDecoder;
import org.webpki.cbor.CBOREncrypter;
import org.webpki.cbor.CBORFloatingPoint;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORNull;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORSigner;
import org.webpki.cbor.CBORSymKeyDecrypter;
import org.webpki.cbor.CBORSymKeyEncrypter;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORTypes;
import org.webpki.cbor.CBORValidator;
import org.webpki.cbor.CBORX509Decrypter;
import org.webpki.cbor.CBORX509Encrypter;
import org.webpki.cbor.CBORX509Signer;
import org.webpki.cbor.CBORX509Validator;

import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.KeyTypes;

import org.webpki.util.HexaDecimal;
import org.webpki.util.UTF8;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;

import java.security.cert.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.TimeZone;

/**
 * This is a demonstration and test application for the WebPKI CBOR, CSF and CEF components.
 */
public class MainActivity extends AppCompatActivity {

    enum KEY_TYPES {EC_KEY, RSA_KEY, PKI, SYMMETRIC_KEY}

    static final String HTML_HEADER =
        "<html><head><style type='text/css'>" +
        "body {margin:12pt;font-size:10pt;color:#000000;font-family:Roboto;background-color:white}" +
        "div {text-align:center;padding:3pt 6pt 3pt 6pt;border-width:1px;margin-bottom:15pt;" +
        "border-style:solid;border-color:#a0a0a0;box-shadow:3pt 3pt 3pt #d0d0d0;" +
        "background:linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);" +
        "border-radius:3pt;margin-left:auto;margin-right:auto}" +
        "</style>" +
        "<script type='text/javascript'>\n" +
        "'use strict';\n";

    static final String HTML_BODY =
        "</script></head><body>" +
        "<div style='width:4em;margin-left:0pt' onclick='WebPKI.homeScreen()'>Home</div>" +
        "<h3 style='text-align:center'>";

    WebView webView;

    static WebViewAssetLoader.PathHandler ph = path -> null;

    byte[] currentHtml;

    final WebViewAssetLoader webLoader = new WebViewAssetLoader.Builder()
            .addPathHandler("/main/", new WebViewAssetLoader.PathHandler() {
                @Nullable
                @Override
                public WebResourceResponse handle(@NonNull String path) {
                    return new WebResourceResponse("text/html",
                                                   "utf-8",
                                                   new ByteArrayInputStream(currentHtml));
                }
            })
        .build();

    void loadHtml(final String javaScript, final String header, final String body) {
        try {
            currentHtml = UTF8.encode(new StringBuilder(HTML_HEADER)
                    .append(javaScript)
                    .append(HTML_BODY)
                    .append(header)
                    .append("</h3>")
                    .append(body)
                    .append("</body></html>").toString());
        } catch (Exception e) {
            Log.e("HTM", e.getMessage());
            return;
        }
        runOnUiThread(() -> webView.loadUrl("https://appassets.androidplatform.net/main/"));
    }

    String htmlIze(String s) {
        StringBuilder res = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '\n') {
                res.append("&#10;");
            } else if (c == '"') {
                res.append("&quot;");
            } else if (c == '&') {
                res.append("&amp;");
            } else if (c == '>') {
                res.append("&gt;");
            } else if (c == '<') {
                res.append("&lt;");
            } else {
                res.append(c);
            }
        }
        return res.toString();
    }

    void errorView(Exception e) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter printerWriter = new PrintWriter(baos);
        e.printStackTrace(printerWriter);
        printerWriter.flush();
        String msg = "Error description not available";
        try {
            msg = htmlIze(baos.toString("utf-8"));
            msg = msg.replace("Exception: ", "Exception:\n");
        } catch (Exception e2) {
        }
        loadHtml("", "ERROR", "<pre style='color:red'>" + msg + "</pre>");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        webView = (WebView) findViewById(R.id.webView);
        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webView.addJavascriptInterface (this, "WebPKI");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view,
                                                              WebResourceRequest request) {
                return webLoader.shouldInterceptRequest(request.getUrl());
            }
        });
        homeScreen();
        String version = "?";
        try {
            new RawReader(getApplicationContext());
            version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
        }
        setTitle("CBOR, CSF and CEF Demo V" + version);
     }

    void addCommandButton(StringBuilder buffer, String button, String executor) {
        buffer.append("<div style='width:15em' onclick='WebPKI.")
                .append(executor)
                .append("'>")
                .append(button)
                .append("</div>");
    }
    String executeButton(String executor) {
        return "<div style='width:6em;margin-bottom:0pt;margin-top:15pt' onclick='WebPKI." +
                executor + "'>Execute!</div>";
    }

    @JavascriptInterface
    public void homeScreen() {
        StringBuilder s = new StringBuilder();
        addCommandButton(s, "Sign CBOR Data", "signData()");
        addCommandButton(s, "Verify CSF Signature", "verifySignature()");
        addCommandButton(s, "Encrypt Arbitrary Data", "encryptData()");
        addCommandButton(s, "Decrypt CEF Encoded Data", "decryptData()");
        loadHtml("", "CBOR Signatures and Encryption", s.toString());
    }

     void verifySignature(String cborData) {
        loadHtml("", "Verify CBOR (CSF) Signature",
                 "<textarea id='cborData' style='width:100%;height:60%;word-break:break-all'>" +
                 htmlIze(cborData) +
                 "</textarea>" +
                 executeButton("doVerify(document.getElementById(\"cborData\").value)"));
    }

    CBORMap getStandardMessage() throws IOException {
        int index = 0;
        SimpleDateFormat sdf = new SimpleDateFormat("'CBOR Sample' yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return new CBORMap()
                .setObject(new CBORInteger(++index),
                           new CBORString(sdf.format(new Date().getTime())))
                .setObject(new CBORInteger(++index),
                           new CBORBytes(
                        new byte[]{(byte)0x50, (byte)0x42, (byte)0x12, (byte)0x3a, (byte)0x65,
                                   (byte)0x93, (byte)0x60, (byte)0x16, (byte)0x3a, (byte)0xd8,
                                   (byte)0x84, (byte)0x71, (byte)0xf8, (byte)0xc0, (byte)0x89,
                                   (byte)0x91, (byte)0x3b}))
                .setObject(new CBORInteger(++index),
                           new CBORBigInteger(new BigInteger("-653625362513652165356656")))
                .setObject(new CBORInteger(++index), new CBORArray()
                        .addObject(new CBORNull())
                        .addObject(new CBORBoolean(true))
                        .addObject(new CBORBoolean(false)))
                .setObject(new CBORInteger(++index), new CBORArray()
                        .addObject(new CBORFloatingPoint(0.0))
                        .addObject(new CBORFloatingPoint(2.0000001e+38))
                        .addObject(new CBORFloatingPoint(Double.NEGATIVE_INFINITY)));
    }

    @JavascriptInterface
    public void verifySignature() throws Exception {
        // Show a pre-defined signed object as default
        CBORMap dataToSign = getStandardMessage();
        verifySignature(new CBORAsymKeySigner(RawReader.ecKeyPair.getPrivate())
                .setPublicKey(RawReader.ecKeyPair.getPublic())
                .sign(new CBORInteger(dataToSign.size() + 1), dataToSign).toString());
    }

    PublicKey publicKey;
    X509Certificate[] certificatePath;
    int algorithm;
    CBORObject keyId;

    String signatureType;
    String keyInfo;

    public static CBORMap unwrapOptionalTag(CBORObject rawContainer) throws IOException {
        // It might be tagged
        if (rawContainer.getType() == CBORTypes.TAG) {
            CBORObject container = rawContainer.getTag().getObject();
            if (container.getType() == CBORTypes.ARRAY) {
                container = container.getArray().getObject(1);
            }
            return container.getMap();
        }
        return rawContainer.getMap();
    }

    @JavascriptInterface
    public void doVerify(String cborData) {
        try {
            // Normally you SHOULD know what to expect so this code is a bit over-the-top
            CBORObject signedData = CBORDiagnosticNotationDecoder.decode(cborData);
            CBORMap coreMap = unwrapOptionalTag(signedData);
            CBORObject csfLabel = null;
            publicKey = null;
            certificatePath = null;
            algorithm = 0;
            keyId = null;
            for (CBORObject key : coreMap.getKeys()) {
                CBORObject value = coreMap.getObject(key);
                if (value.getType() != CBORTypes.MAP) continue;
                CBORMap csfCandidate = value.getMap();
                if (!csfCandidate.hasKey(CBORCryptoConstants.ALGORITHM_LABEL)) continue;
                value = csfCandidate.getObject(CBORCryptoConstants.ALGORITHM_LABEL);
                if (value.getType() != CBORTypes.INTEGER) continue;
                int tempAlgorithm = value.getInt();
                CBORObject tempKeyId = null;
                if (csfCandidate.hasKey(CBORCryptoConstants.KEY_ID_LABEL)) {
                    tempKeyId = csfCandidate.getObject(CBORCryptoConstants.KEY_ID_LABEL);
                }
                if (!csfCandidate.hasKey(CBORCryptoConstants.SIGNATURE_LABEL)) continue;
                value = csfCandidate.getObject(CBORCryptoConstants.SIGNATURE_LABEL);
                if (value.getType() != CBORTypes.BYTE_STRING) continue;
                PublicKey tempPublicKey = null;
                if (csfCandidate.hasKey(CBORCryptoConstants.PUBLIC_KEY_LABEL)) {
                    try {
                        tempPublicKey = CBORPublicKey.convert(
                                csfCandidate.getObject(CBORCryptoConstants.PUBLIC_KEY_LABEL));
                    } catch (Exception e) {
                        continue;
                    }
                }
                X509Certificate[] tempCertificatePath = null;
                if (csfCandidate.hasKey(CBORCryptoConstants.CERT_PATH_LABEL)) {
                    try {
                        tempCertificatePath = CBORCryptoUtils.decodeCertificateArray(
                                csfCandidate.getObject(CBORCryptoConstants.CERT_PATH_LABEL).getArray());
                    } catch (Exception e) {
                        continue;
                    }
                }
                if (csfLabel != null) {
                    throw new IOException("Multiple CSFs?");
                }
                csfLabel = key;
                keyId = tempKeyId;
                publicKey = tempPublicKey;
                algorithm = tempAlgorithm;
                certificatePath = tempCertificatePath;
            }
            if (csfLabel == null) {
                throw new IOException("Didn't find any CSF object!");
            }
            boolean hmacFlag = false;
            for (HmacAlgorithms hmacAlg : HmacAlgorithms.values()) {
                if (hmacAlg != HmacAlgorithms.HMAC_SHA1 && hmacAlg.getCoseAlgorithmId() == algorithm) {
                    hmacFlag = true;
                    break;
                }
            }
            CBORValidator validator = null;
            if (hmacFlag) {
                validator = new CBORHmacValidator(RawReader.secretKey);
                keyInfo = HexaDecimal.encode(RawReader.secretKey);
                signatureType = "HMAC";
            } else if (certificatePath != null) {
                validator = new CBORX509Validator((certificatePath, algorithm) -> { });
                keyInfo = certificatePath[0].toString();
                signatureType = "CERTIFICATE";
            } else {
                validator = new CBORAsymKeyValidator((optionalPublicKey,
                                                      optionalKeyId,
                                                      algorithm) -> {
                    if (optionalPublicKey == null) {
                        publicKey = (algorithm.getKeyType() == KeyTypes.EC ?
                                RawReader.ecKeyPair : RawReader.rsaKeyPair).getPublic();
                    } else {
                        publicKey = optionalPublicKey;
                    }
                    keyInfo = publicKey.toString();
                    return publicKey;
                });
                signatureType = "ASYMMETRIC";
            }
            // Clone the data to make sure the not-read check can do its work
            validator.setTagPolicy(CBORCryptoUtils.POLICY.OPTIONAL, null)
                     .setCustomDataPolicy(CBORCryptoUtils.POLICY.OPTIONAL, null)
                     .validate(csfLabel, CBORObject.decode(signedData.encode()));

            loadHtml("",
                    "Valid Signature!",
                    "<p><i>Signature type:</i> " + signatureType +
                    "</p><p><i>Signature key:</i></p><pre style='color:green'>" +
                            htmlIze(keyInfo) + "</pre>");
        } catch (Exception e) {
            errorView(e);
        }
    }

    @JavascriptInterface
    public void signData() throws IOException {
        StringBuilder choices = new StringBuilder();
        for (KEY_TYPES sigType : KEY_TYPES.values()) {
            choices.append("<tr><td><input type='radio' name='keyType' value='")
                   .append(sigType.toString())
                   .append(sigType == KEY_TYPES.EC_KEY ? "' checked>" : "'>")
                   .append(sigType.toString())
                   .append("</td></tr>");
        }
        loadHtml("function getRadio() {\n" +
                        "  return document.querySelector('input[name = \"keyType\"]:checked').value;\n" +
                        "}",
                "Sign CBOR Data using CSF",
                "<textarea id='cborData' style='width:100%;height:40%;word-break:break-all'>" +
                htmlIze(getStandardMessage().toString()) +
                "</textarea>" +
                "<table style='margin-top:10pt;margin-left:auto;margin-right:auto;font-size:10pt'>" +
                choices.toString() +
                "</table>" +
                executeButton("doSign(document.getElementById(\"cborData\").value, getRadio())"));
    }

    @JavascriptInterface
    public void doSign(String cborData, String keyType) {
        try {
            KEY_TYPES sigType = KEY_TYPES.valueOf(keyType);
            final CBORObject dataToBeSigned = CBORDiagnosticNotationDecoder.decode(cborData);
            CBORMap cborMap = unwrapOptionalTag(dataToBeSigned);
            CBORObject csfLabel = new CBORInteger(0);
            if (cborMap.size() > 0) {
                csfLabel = cborMap.getKeys()[cborMap.size() - 1];
                if (csfLabel.getType() == CBORTypes.INTEGER) {
                    BigInteger value = csfLabel.getBigInteger();
                    value = value.compareTo(BigInteger.ZERO) >= 0 ?
                        value.add(BigInteger.ONE) : value.subtract(BigInteger.ONE);
                    csfLabel = new CBORBigInteger(value);
                } else {
                    csfLabel = new CBORString("signature");
                }
            }
            CBORSigner signer;
            switch (sigType) {
                case EC_KEY:
                case RSA_KEY:
                    KeyPair keyPair = sigType == KEY_TYPES.RSA_KEY ?
                                              RawReader.rsaKeyPair : RawReader.ecKeyPair;
                    signer = new CBORAsymKeySigner(keyPair.getPrivate())
                            .setPublicKey(keyPair.getPublic());
                    break;
                case PKI:
                    signer = new CBORX509Signer(RawReader.ecKeyPair.getPrivate(),
                                                RawReader.ecCertPath);
                    break;
                default:
                    signer = new CBORHmacSigner(RawReader.secretKey,
                                                HmacAlgorithms.HMAC_SHA256)
                            .setKeyId(new CBORString(RawReader.secretKeyId));
            }
            signer.setIntercepter(new CBORCryptoUtils.Intercepter() {
                @Override public CBORObject wrap(CBORMap mapToSign) {
                    return dataToBeSigned;
                }
            });
            verifySignature(signer.sign(csfLabel, cborMap).toString());
        } catch (Exception e) {
            errorView(e);
        }
    }

    @JavascriptInterface
    public void encryptData() {
        StringBuilder choices = new StringBuilder();
        for (KEY_TYPES encType : KEY_TYPES.values()) {
            choices.append("<tr><td><input type='radio' name='keyType' value='")
                    .append(encType.toString())
                    .append(encType == KEY_TYPES.EC_KEY ? "' checked>" : "'>")
                    .append(encType.toString())
                    .append("</td></tr>");
        }
        loadHtml("function getRadio() {\n" +
                        "  return document.querySelector('input[name = \"keyType\"]:checked').value;\n" +
                        "}",
                "Encrypt <i>Arbitary</i> Data using CEF",
                "<textarea id='cborData' style='width:100%;height:40%;word-break:break-all'>" +
                htmlIze(
                        "{\n" +
                        "  \"Encryption is fun\": true,\n" +
                        "  \"Encryption is easy\": \"Well...\"\n" +
                        "}") +
                "</textarea>" +
                "<table style='margin-top:10pt;margin-left:auto;margin-right:auto;font-size:10pt'>" +
                choices.toString() +
                "</table>" +
                executeButton("doEncrypt(document.getElementById(\"cborData\").value, getRadio())"));
    }

    @JavascriptInterface
    public void doEncrypt(String arbitraryData, String keyType) {
        try {
            byte[] unencryptedData = UTF8.encode(arbitraryData);
            KEY_TYPES encType = KEY_TYPES.valueOf(keyType);
            CBOREncrypter encrypter;
            switch (encType) {
                case EC_KEY:
                case RSA_KEY:
                    encrypter = new CBORAsymKeyEncrypter(
                            (encType == KEY_TYPES.RSA_KEY ?
                                     RawReader.rsaKeyPair : RawReader.ecKeyPair).getPublic(),
                            encType == KEY_TYPES.RSA_KEY ?
                    KeyEncryptionAlgorithms.RSA_OAEP_256 : KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                                          ContentEncryptionAlgorithms.A128GCM)
                        .setPublicKeyOption(true);
                    break;
                case PKI:
                    encrypter = new CBORX509Encrypter(RawReader.ecCertPath,
                                                      KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                                                      ContentEncryptionAlgorithms.A128GCM);
                    break;
                default:
                    encrypter = new CBORSymKeyEncrypter(RawReader.secretKey,
                                                        ContentEncryptionAlgorithms.A128CBC_HS256)
                        .setKeyId(RawReader.secretKeyId);
            }
            decryptData(encrypter.encrypt(unencryptedData).toString());
        } catch (Exception e) {
            errorView(e);
        }
    }

    void decryptData(String cborEncryptionObject) {
        loadHtml("", "Decrypt CEF Encoded Data",
                "<textarea id='cborData' style='width:100%;height:60%;word-break:break-all'>" +
                htmlIze(cborEncryptionObject) +
                "</textarea>" +
                executeButton("doDecrypt(document.getElementById(\"cborData\").value)"));
    }

    @JavascriptInterface
    public void decryptData() throws Exception {
        // Show a pre-defined encrypted object as default
        decryptData(RawReader.getCBORText(R.raw.a256_a128cbc_hs256_kid_cbor));
    }

    @JavascriptInterface
    public void doDecrypt(String cborEncryptionObject) {
        try {
            CBORObject cefObject = CBORDiagnosticNotationDecoder.decode(cborEncryptionObject);
            CBORMap cefMap = unwrapOptionalTag(cefObject);
            CBORDecrypter decrypter;
            String encryptionInfo;
            if (cefMap.hasKey(CBORCryptoConstants.KEY_ENCRYPTION_LABEL)) {
                if (cefMap.getObject(CBORCryptoConstants.KEY_ENCRYPTION_LABEL)
                        .getMap().hasKey(CBORCryptoConstants.CERT_PATH_LABEL)) {
                    encryptionInfo = "PKI";
                    decrypter = new CBORX509Decrypter(new CBORX509Decrypter.DecrypterImpl() {
                        @Override
                        public PrivateKey locate(X509Certificate[] certificatePath,
                                                 KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                            return RawReader.ecKeyPair.getPrivate();
                        }

                        @Override
                        public byte[] decrypt(PrivateKey privateKey,
                                              byte[] optionalEncryptedKey,
                                              PublicKey optionalEphemeralKey,
                                              KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                              ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                            return EncryptionCore.receiverKeyAgreement(true,
                                                                       keyEncryptionAlgorithm,
                                                                       contentEncryptionAlgorithm,
                                                                       optionalEphemeralKey,
                                                                       privateKey,
                                                                       optionalEncryptedKey);
                        }
                    });
                } else {
                    encryptionInfo = "ASYMMETRIC";
                    decrypter = new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.DecrypterImpl() {
                        @Override
                        public PrivateKey locate(PublicKey optionalPublicKey,
                                                 CBORObject optionalKeyId,
                                                 KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                            return (keyEncryptionAlgorithm.isRsa() ?
                                    RawReader.rsaKeyPair : RawReader.ecKeyPair).getPrivate();
                        }

                        @Override
                        public byte[] decrypt(PrivateKey privateKey,
                                              byte[] optionalEncryptedKey,
                                              PublicKey optionalEphemeralKey,
                                              KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                              ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                            return EncryptionCore.receiverKeyAgreement(true,
                                                                       keyEncryptionAlgorithm,
                                                                       contentEncryptionAlgorithm,
                                                                       optionalEphemeralKey,
                                                                       privateKey,
                                                                       optionalEncryptedKey);
                        }
                    });
                }
            } else {
                encryptionInfo = "SYMMETRIC";
                decrypter = new CBORSymKeyDecrypter(RawReader.secretKey);
            }
            String decryptedData = UTF8.decode(decrypter.decrypt(cefObject));
            loadHtml("",
                    "Decrypted Data",
                    "<p><i>Decryption type:</i> " + encryptionInfo +
                            "</p><pre style='color:blue'>" + htmlIze(decryptedData) + "</pre>");
        } catch (Exception e) {
            errorView(e);
        }
    }
}
