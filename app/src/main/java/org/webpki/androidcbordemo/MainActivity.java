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

import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTypes;
import org.webpki.cbor.CBORValidator;
import org.webpki.cbor.CBORX509Validator;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.KeyTypes;
import org.webpki.util.HexaDecimal;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.KeyPair;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

/**
 * This is a demonstration and test application for the WebPKI CBOR, CSF and CEF components.
 */
public class MainActivity extends AppCompatActivity {

    enum SIG_TYPES {EC_KEY, RSA_KEY, PKI, SYMMETRIC_KEY}

    enum ENC_TYPES {EC_KEY, RSA_KEY, SYMMETRIC_KEY}

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

    static WebViewAssetLoader.PathHandler ph = new WebViewAssetLoader.PathHandler() {
        @Nullable
        @Override
        public WebResourceResponse handle(@NonNull String path) {
            return null;
        }
    };

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
            currentHtml = new StringBuilder(HTML_HEADER)
                    .append(javaScript)
                    .append(HTML_BODY)
                    .append(header)
                    .append("</h3>")
                    .append(body)
                    .append("</body></html>").toString().getBytes("utf-8");
        } catch (Exception e) {
            Log.e("HTM", e.getMessage());
            return;
        }
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                webView.loadUrl("https://appassets.androidplatform.net/main/");
            }
        });
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

    void errorViev(Exception e) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter printerWriter = new PrintWriter(baos);
        e.printStackTrace(printerWriter);
        printerWriter.flush();
        String msg = "Error description not available";
        try {
            msg = htmlIze(baos.toString("utf-8"));
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
        setTitle("JSON, JSF and JEF Demo V" + version);
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

    @JavascriptInterface
    public void verifySignature() throws Exception {
        // Show a pre-defined signed object as default
        verifySignature(RawReader.getCBORText(R.raw.p256_es256_pub_cbor));
    }

    PublicKey publicKey;
    X509Certificate[] certificatePath;
    int algorithm;
    CBORObject keyId;

    String signatureType;
    String keyInfo;

    @JavascriptInterface
    public void doVerify(String cborData) {
        try {
            // Normally you SHOULD know what to expect so this code is a bit over-the-top
            CBORObject signedData = CBORDiagnosticParser.parse(cborData);
            CBORMap coreMap = CBORCryptoUtils.unwrapContainerMap(signedData);
            CBORObject csfLabel = null;
            for (CBORObject key : coreMap.getKeys()) {
                publicKey = null;
                certificatePath = null;
                algorithm = 0;
                keyId = null;
                CBORObject value = coreMap.getObject(key);
                if (value.getType() != CBORTypes.MAP) continue;
                CBORMap csfCandidate = value.getMap();
                if (!csfCandidate.hasKey(CBORCryptoConstants.ALGORITHM_LABEL)) continue;
                value = csfCandidate.getObject(CBORCryptoConstants.ALGORITHM_LABEL);
                if (value.getType() != CBORTypes.INTEGER) continue;
                algorithm = value.getInt();
                if (csfCandidate.hasKey(CBORCryptoConstants.KEY_ID_LABEL)) {
                    keyId = csfCandidate.getObject(CBORCryptoConstants.KEY_ID_LABEL);
                }
                if (!csfCandidate.hasKey(CBORCryptoConstants.SIGNATURE_LABEL)) continue;
                value = csfCandidate.getObject(CBORCryptoConstants.SIGNATURE_LABEL);
                if (value.getType() != CBORTypes.BYTE_STRING) continue;
                if (csfCandidate.hasKey(CBORCryptoConstants.PUBLIC_KEY_LABEL)) {
                    try {
                        publicKey = CBORPublicKey.decode(
                                csfCandidate.getObject(CBORCryptoConstants.PUBLIC_KEY_LABEL));
                    } catch (Exception e) {
                        continue;
                    }
                }
                if (csfCandidate.hasKey(CBORCryptoConstants.CERT_PATH_LABEL)) {
                    try {
                        certificatePath = CBORCryptoUtils.decodeCertificateArray(
                                csfCandidate.getObject(CBORCryptoConstants.CERT_PATH_LABEL).getArray());
                    } catch (Exception e) {
                        continue;
                    }
                }
                if (csfLabel != null) {
                    throw new IOException("Multiple CSFs?");
                }
                csfLabel = key;
            }
            if (csfLabel == null) {
                throw new IOException("Didn't find any CSF object!");
            }
            boolean hmacFlag = false;
            for (HmacAlgorithms hmacAlg : HmacAlgorithms.values()) {
                if (hmacAlg.getCoseAlgorithmId() == algorithm) {
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
                validator = new CBORX509Validator(new CBORX509Validator.Parameters() {
                    @Override
                    public void verify(X509Certificate[] certificatePath,
                                       AsymSignatureAlgorithms algorithm)
                            throws IOException, GeneralSecurityException {
                    }
                });
                keyInfo = certificatePath[0].toString();
                signatureType = "CERTIFICATE";
            } else {
                validator = new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
                    @Override
                    public PublicKey locate(PublicKey optionalPublicKey,
                                            CBORObject optionalKeyId,
                                            AsymSignatureAlgorithms algorithm)
                            throws IOException, GeneralSecurityException {
                        if (optionalPublicKey == null) {
                            publicKey = (algorithm.getKeyType() == KeyTypes.EC ?
                                    RawReader.ecKeyPair : RawReader.rsaKeyPair).getPublic();
                        } else {
                            publicKey = optionalPublicKey;
                        }
                        keyInfo = publicKey.toString();
                        return publicKey;
                    }
                });
                signatureType = "ASYMMETRIC";
            }
            validator.validate(csfLabel, signedData);

            loadHtml("",
                    "Valid Signature!",
                    "<p><i>Signature type:</i> " + signatureType +
                    "</p><p><i>Signature key:</i></p><pre style='color:green'>" +
                            htmlIze(keyInfo) + "</pre>");
        } catch (Exception e) {
            errorViev(e);
        }
    }

    @JavascriptInterface
    public void signData() {
        StringBuilder choices = new StringBuilder();
        for (SIG_TYPES sigType : SIG_TYPES.values()) {
            choices.append("<tr><td><input type='radio' name='keyType' value='")
                   .append(sigType.toString())
                   .append(sigType == SIG_TYPES.EC_KEY ? "' checked>" : "'>")
                   .append(sigType.toString())
                   .append("</td></tr>");
        }
        loadHtml("function getRadio() {\n" +
                        "  return document.querySelector('input[name = \"keyType\"]:checked').value;\n" +
                        "}",
                "Sign JSON Data using JSF",
                "<textarea id='cborData' style='width:100%;height:40%;word-break:break-all'>" +
                htmlIze(
                        "{\n" +
                        "  \"timeStamp\": \"2019-03-16T11:23:06Z\",\n" +
                        "  \"escapeMe\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n" +
                        "  \"numbers\": [1e+30,4.5,6]\n" +
                        "}") +
                "</textarea>" +
                "<table style='margin-top:10pt;margin-left:auto;margin-right:auto;font-size:10pt'>" +
                choices.toString() +
                "</table>" +
                executeButton("doSign(document.getElementById(\"cborData\").value, getRadio())"));
    }

    @JavascriptInterface
    public void doSign(String cborData, String keyType) {
        try {
            SIG_TYPES sigType = SIG_TYPES.valueOf(keyType);
            JSONObjectWriter writer = new JSONObjectWriter(JSONParser.parse(cborData));
            switch (sigType) {
                case EC_KEY:
                case RSA_KEY:
                    KeyPair keyPair = sigType == SIG_TYPES.RSA_KEY ?
                                              RawReader.rsaKeyPair : RawReader.ecKeyPair;
                    writer.setSignature(new JSONAsymKeySigner(keyPair.getPrivate())
                            .setPublicKey(keyPair.getPublic()));
                    break;
                case PKI:
                    writer.setSignature(new JSONX509Signer(RawReader.ecKeyPair.getPrivate(),
                                                           RawReader.ecCertPath));
                    break;
                default:
                    writer.setSignature(new JSONHmacSigner(RawReader.secretKey,
                                                             HmacAlgorithms.HMAC_SHA256).setKeyId(RawReader.secretKeyId));
            }
            verifySignature(writer.toString());
        } catch (Exception e) {
            errorViev(e);
        }
    }

    @JavascriptInterface
    public void encryptData() {
        StringBuilder choices = new StringBuilder();
        for (ENC_TYPES encType : ENC_TYPES.values()) {
            choices.append("<tr><td><input type='radio' name='keyType' value='")
                    .append(encType.toString())
                    .append(encType == ENC_TYPES.EC_KEY ? "' checked>" : "'>")
                    .append(encType.toString())
                    .append("</td></tr>");
        }
        loadHtml("function getRadio() {\n" +
                        "  return document.querySelector('input[name = \"keyType\"]:checked').value;\n" +
                        "}",
                "Encrypt <i>Arbitary</i> Data using JEF",
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
            byte[] unencryptedData = arbitraryData.getBytes("UTF-8");
            ENC_TYPES encType = ENC_TYPES.valueOf(keyType);
            JSONObjectWriter writer = null;
            switch (encType) {
                case EC_KEY:
                case RSA_KEY:
                    PublicKey publicKey = (encType == ENC_TYPES.RSA_KEY ?
                                                   RawReader.rsaKeyPair : RawReader.ecKeyPair).getPublic();
                    writer = JSONObjectWriter.createEncryptionObject(unencryptedData,
                                                                     ContentEncryptionAlgorithms.A128GCM,
                                                                     new JSONAsymKeyEncrypter(publicKey,
                                                                     encType == ENC_TYPES.RSA_KEY ?
                             KeyEncryptionAlgorithms.RSA_OAEP_256 : KeyEncryptionAlgorithms.ECDH_ES_A256KW));
                    break;
                default:
                    writer = JSONObjectWriter.createEncryptionObject(unencryptedData,
                                                                     ContentEncryptionAlgorithms.A128CBC_HS256,
                                                                     new JSONSymKeyEncrypter(RawReader.secretKey).setKeyId(RawReader.secretKeyId));
            }
            decryptData(writer.toString());
        } catch (Exception e) {
            errorViev(e);
        }
    }

    void decryptData(String jsonEncryptionObject) {
        loadHtml("", "Decrypt JEF Encoded Data",
                "<textarea id='cborData' style='width:100%;height:60%;word-break:break-all'>" +
                htmlIze(jsonEncryptionObject) +
                "</textarea>" +
                executeButton("doDecrypt(document.getElementById(\"cborData\").value)"));
    }

    @JavascriptInterface
    public void decryptData() throws Exception {
        // Show a pre-defined encrypted object as default
        decryptData(RawReader.getStringResource(R.raw.a128cbc_hs256_json));
    }

    @JavascriptInterface
    public void doDecrypt(String jsonEncryptionObject) {
        try {
            JSONObjectReader jefObject = JSONParser.parse(jsonEncryptionObject);
            JSONCryptoHelper.Options options = new JSONCryptoHelper.Options()
                .setPublicKeyOption(jefObject.hasProperty(JSONCryptoHelper.KEY_ENCRYPTION_JSON) ?
     JSONCryptoHelper.PUBLIC_KEY_OPTIONS.OPTIONAL : JSONCryptoHelper.PUBLIC_KEY_OPTIONS.PLAIN_ENCRYPTION)
                .setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.OPTIONAL);
            JSONDecryptionDecoder encryptionObject = jefObject.getEncryptionObject(options);
            String decryptedData = null;
            if (encryptionObject.isSharedSecret()) {
                decryptedData = new String(encryptionObject.getDecryptedData(RawReader.secretKey),"UTF-8");
            } else {
                KeyPair keyPair = encryptionObject.getKeyEncryptionAlgorithm().isRsa() ?
                                                                  RawReader.rsaKeyPair : RawReader.ecKeyPair;
                decryptedData = new String(encryptionObject.getDecryptedData(keyPair.getPrivate()),"UTF-8");
            }
            loadHtml("",
                    "Decrypted Data",
                    "<p><i>Decryption type:</i> " + (encryptionObject.isSharedSecret() ? "SYMMETRIC_KEY" : "ASYMMETRIC_KEY") + "</p><pre style='color:blue'>" + htmlIze(decryptedData) + "</pre>");
        } catch (Exception e) {
            errorViev(e);
        }
    }
}
