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

import android.util.Base64;
import android.util.Log;

import android.webkit.JavascriptInterface;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebResourceRequest;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.webkit.WebViewAssetLoader;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;

import java.security.cert.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

import java.util.GregorianCalendar;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORBigInt;
import org.webpki.cbor.CBORBoolean;
import org.webpki.cbor.CBORBytes;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORCryptoUtils;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORDecrypter;
import org.webpki.cbor.CBORDiagnosticNotation;
import org.webpki.cbor.CBOREncrypter;
import org.webpki.cbor.CBORFloat;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInt;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORNull;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORSigner;
import org.webpki.cbor.CBORSymKeyDecrypter;
import org.webpki.cbor.CBORSymKeyEncrypter;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORValidator;
import org.webpki.cbor.CBORX509Decrypter;
import org.webpki.cbor.CBORX509Encrypter;
import org.webpki.cbor.CBORX509Signer;
import org.webpki.cbor.CBORX509Validator;

import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;
import org.webpki.crypto.KeyTypes;

import org.webpki.util.HexaDecimal;
import org.webpki.util.ISODateTime;
import org.webpki.util.UTF8;

/**
 * This is a demonstration and test application for the WebPKI CBOR, CSF and CEF components.
 */
public class MainActivity extends AppCompatActivity {

    final static String TOOLBAR_HTML = """
<!DOCTYPE html><html>
<head><meta name='viewport' content='width=device-width, initial-scale=1.0'></head>
<body style='box-sizing:border-box;background:#ffffdd;margin:0;border-width:0.1em 0 0.1em 0;border-color:#b0b0b0;border-style:solid'>
<div style='display:table-cell'>
<svg style='display:block;height:3em;padding:5px 0.5em' xmlns="http://www.w3.org/2000/svg" viewBox='0 0 104 36' version="1.1">
<title>CBOR Logotype</title>
<defs><filter id="shadow">
<feDropShadow dx="1" dy="1" stdDeviation="1" flood-opacity="0.5"/>
</filter></defs>
<g filter="url(#shadow)">
<g fill="#E1E3FD" stroke="#5D5DFF" stroke-width="1.5">
<path d="m 24.458333,23.08073 q -0.527343,4.511719 -3.339843,6.972657 -2.792969,2.441406\
-7.441407,2.441406 -5.0390622,0 -8.0859372,-3.613281 Q 2.5638021,25.26823 \
2.5638021,19.213543 v -2.734375 q 0,-3.964844 1.40625,-6.9726563 1.4257812,\
-3.0078125 4.0234375,-4.609375 2.5976564,-1.6210938 6.0156254,-1.6210938 \
4.53125,0 7.265625,2.5390625 2.734375,2.5195313 3.183593,6.9921876 H 20.688802 \
Q 20.200521,9.4088554 18.559896,7.8854179 16.938802,6.3619804 14.009115,6.3619804 \
q -3.59375,0 -5.6445317,2.65625 -2.03125,2.6562496 -2.03125,7.5585936 v 2.753906 \
q 0,4.628907 1.9335938,7.363282 1.9335939,2.734375 5.4101559,2.734375 3.125,0 \
4.785157,-1.40625 1.679687,-1.425782 2.226562,-4.941407 z"/>
<path d="M 29.575521,32.104168 V 3.6666679 h 9.296875 q 4.628906,0 6.953125,\
1.9140625 2.34375,1.9140625 2.34375,5.6640626 0,1.992187 -1.132813,3.535156 \
-1.132812,1.523438 -3.085937,2.363281 2.304687,0.644532 3.632812,2.460938 \
1.347657,1.796875 1.347657,4.296875 0,3.828125 -2.480469,6.015625 \
-2.480469,2.1875 -7.011719,2.1875 z m 3.75,-13.300781 v 10.234375 h 6.191406 \
q 2.617188,0 4.121094,-1.347657 1.523437,-1.367187 1.523437,-3.75 0,-5.136718 \
-5.585937,-5.136718 z m 0,-3.007813 h 5.664062 q 2.460938,0 3.925782,-1.230469 \
1.484375,-1.230468 1.484375,-3.339843 0,-2.3437503 -1.367188,-3.3984378 -1.367187,\
-1.0742188 -4.160156,-1.0742188 h -5.546875 z"/>
<path d="m 76.352865,18.803387 q 0,4.179687 -1.40625,7.304687 -1.40625,3.105469 \
-3.984375,4.746094 -2.578125,1.640625 -6.015625,1.640625 -3.359375,0 -5.957032,\
-1.640625 -2.597656,-1.660156 -4.042968,-4.707031 -1.425782,-3.066407 -1.464844,\
-7.089844 v -2.050781 q 0,-4.101563 1.425781,-7.2460941 1.425781,-3.1445312 \
4.023438,-4.8046875 2.617187,-1.6796875 5.976562,-1.6796875 3.417969,0 6.015625,\
1.6601563 2.617188,1.640625 4.023438,4.7851562 1.40625,3.1249996 1.40625,7.2851566 \
z m -3.730469,-1.835938 q 0,-5.058594 -2.03125,-7.7539061 -2.03125,-2.7148437 \
-5.683594,-2.7148437 -3.554687,0 -5.605469,2.7148437 -2.03125,2.6953121 -2.089843,\
7.5000001 v 2.089844 q 0,4.902343 2.050781,7.714843 2.070312,2.792969 5.683594,\
2.792969 3.632812,0 5.625,-2.636719 1.992187,-2.65625 2.050781,-7.597656 z"/>
<path d="M 92.407552,20.600262 H 85.727865 V 32.104168 H 81.958333 V 3.6666679 \
h 9.414063 q 4.804687,0 7.382812,2.1875 2.597652,2.1875 2.597652,6.3671871 0,\
2.65625 -1.445308,4.628907 -1.425781,1.972656 -3.984375,2.949218 l 6.679683,\
12.070313 v 0.234375 h -4.023433 z m -6.679687,-3.066407 h 5.761718 q 2.792969,0 \
4.433594,-1.445312 1.660156,-1.445313 1.660156,-3.867188 0,-2.6367183 -1.582031,\
-4.0429683 -1.5625,-1.40625 -4.53125,-1.4257813 h -5.742187 z"/>
  </g>
  </g>
</svg></div>
</body></html>""";

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
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        WebView toolBar = findViewById(R.id.toolbar);
        toolBar.loadData(Base64.encodeToString(
                TOOLBAR_HTML.getBytes(), Base64.NO_PADDING), "text/html", "base64");
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

    CBORMap getStandardMessage() {
        int index = 0;
        return new CBORMap()
                .set(new CBORInt(++index),
                     new CBORString("'CBOR Sample' " +
                             ISODateTime.encode(new GregorianCalendar(),
                                                ISODateTime.LOCAL_NO_SUBSECONDS)))
                .set(new CBORInt(++index),
                           new CBORBytes(
                        new byte[]{(byte)0x50, (byte)0x42, (byte)0x12, (byte)0x3a, (byte)0x65,
                                   (byte)0x93, (byte)0x60, (byte)0x16, (byte)0x3a, (byte)0xd8,
                                   (byte)0x84, (byte)0x71, (byte)0xf8, (byte)0xc0, (byte)0x89,
                                   (byte)0x91, (byte)0x3b}))
                .set(new CBORInt(++index),
                     new CBORBigInt(new BigInteger("-653625362513652165356656")))
                .set(new CBORInt(++index), new CBORArray()
                        .add(new CBORNull())
                        .add(new CBORBoolean(true))
                        .add(new CBORBoolean(false)))
                .set(new CBORInt(++index), new CBORArray()
                        .add(new CBORFloat(0.0))
                        .add(new CBORFloat(2.0000001e+38))
                        .add(CBORFloat.createExtendedFloat(Double.NEGATIVE_INFINITY)));
    }

    @JavascriptInterface
    public void verifySignature() {
        // Show a pre-defined signed object as default
        CBORMap dataToSign = getStandardMessage();
        verifySignature(new CBORAsymKeySigner(RawReader.ecKeyPair.getPrivate())
                .setPublicKey(RawReader.ecKeyPair.getPublic())
                .sign(dataToSign).toString());
    }

    PublicKey publicKey;
    X509Certificate[] certificatePath;
    int algorithm;
    CBORObject keyId;

    String signatureType;
    String keyInfo;

    public static CBORMap unwrapOptionalTag(CBORObject rawContainer) {
        // It might be tagged
        if (rawContainer instanceof CBORTag) {
            CBORObject container = rawContainer.getTag().get();
            if (container instanceof CBORArray) {
                container = container.getArray().get(1);
            }
            return container.getMap();
        }
        return rawContainer.getMap();
    }

    @JavascriptInterface
    public void doVerify(String cborData) {
        try {
            // Normally you SHOULD know what to expect so this code is a bit over-the-top
            CBORObject signedData = CBORDiagnosticNotation.convert(cborData);
            CBORMap coreMap = unwrapOptionalTag(signedData);
            CBORObject csfLabel = null;
            publicKey = null;
            certificatePath = null;
            algorithm = 0;
            keyId = null;
            for (CBORObject key : coreMap.getKeys()) {
                CBORObject value = coreMap.get(key);
                if (!(value instanceof CBORMap)) continue;
                CBORMap csfCandidate = value.getMap();
                if (!csfCandidate.containsKey(CBORCryptoConstants.CXF_ALGORITHM_LBL)) continue;
                value = csfCandidate.get(CBORCryptoConstants.CXF_ALGORITHM_LBL);
                if (!(value instanceof CBORInt)) continue;
                int tempAlgorithm = value.getInt32();
                CBORObject tempKeyId = null;
                if (csfCandidate.containsKey(CBORCryptoConstants.CXF_KEY_ID_LBL)) {
                    tempKeyId = csfCandidate.get(CBORCryptoConstants.CXF_KEY_ID_LBL);
                }
                if (!csfCandidate.containsKey(CBORCryptoConstants.CSF_SIGNATURE_LBL)) continue;
                value = csfCandidate.get(CBORCryptoConstants.CSF_SIGNATURE_LBL);
                if (!(value instanceof CBORBytes)) continue;
                PublicKey tempPublicKey = null;
                if (csfCandidate.containsKey(CBORCryptoConstants.CXF_PUBLIC_KEY_LBL)) {
                    try {
                        tempPublicKey = CBORPublicKey.convert(
                                csfCandidate.get(CBORCryptoConstants.CXF_PUBLIC_KEY_LBL));
                    } catch (Exception e) {
                        continue;
                    }
                }
                X509Certificate[] tempCertificatePath = null;
                if (csfCandidate.containsKey(CBORCryptoConstants.CXF_CERT_PATH_LBL)) {
                    try {
                        tempCertificatePath = CBORCryptoUtils.decodeCertificateArray(
                                csfCandidate.get(CBORCryptoConstants.CXF_CERT_PATH_LBL).getArray());
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
            CBORValidator<?> validator = null;
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
                     .validate(CBORDecoder.decode(signedData.encode()));

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
            final CBORObject dataToBeSigned = CBORDiagnosticNotation.convert(cborData);
            CBORMap cborMap = unwrapOptionalTag(dataToBeSigned);
            CBORSigner<?> signer = switch (sigType) {
                case EC_KEY, RSA_KEY -> {
                    KeyPair keyPair = sigType == KEY_TYPES.RSA_KEY ?
                            RawReader.rsaKeyPair : RawReader.ecKeyPair;
                    yield new CBORAsymKeySigner(keyPair.getPrivate())
                            .setPublicKey(keyPair.getPublic());
                }
                case PKI -> new CBORX509Signer(RawReader.ecKeyPair.getPrivate(),
                        RawReader.ecCertPath);
                default -> new CBORHmacSigner(RawReader.secretKey,
                        HmacAlgorithms.HMAC_SHA256)
                        .setKeyId(new CBORString(RawReader.secretKeyId));
            };
            verifySignature(signer.sign(cborMap).toString());
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
            CBOREncrypter<?> encrypter;
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
                        .setKeyId(new CBORString(RawReader.secretKeyId));
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
    public void decryptData()  {
        // Show a pre-defined encrypted object as default
        decryptData(RawReader.getCBORText(R.raw.a256_a128cbc_hs256_kid_cbor));
    }

    @JavascriptInterface
    public void doDecrypt(String cborEncryptionObject) {
        try {
            CBORObject cefObject = CBORDiagnosticNotation.convert(cborEncryptionObject);
            CBORMap cefMap = unwrapOptionalTag(cefObject);
            CBORDecrypter<?> decrypter;
            String encryptionInfo;
            if (cefMap.containsKey(CBORCryptoConstants.CEF_KEY_ENCRYPTION_LBL)) {
                if (cefMap.get(CBORCryptoConstants.CEF_KEY_ENCRYPTION_LBL)
                        .getMap().containsKey(CBORCryptoConstants.CXF_CERT_PATH_LBL)) {
                    encryptionInfo = "PKI";
                    decrypter = new CBORX509Decrypter(new CBORX509Decrypter.KeyLocator() {
                        @Override
                        public PrivateKey locate(X509Certificate[] certificatePath,
                                                 KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                            return RawReader.ecKeyPair.getPrivate();
                        }

                    });
                } else {
                    encryptionInfo = "ASYMMETRIC";
                    decrypter = new CBORAsymKeyDecrypter(new CBORAsymKeyDecrypter.KeyLocator() {
                        @Override
                        public PrivateKey locate(PublicKey optionalPublicKey,
                                                 CBORObject optionalKeyId,
                                                 KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                            return (keyEncryptionAlgorithm.isRsa() ?
                                    RawReader.rsaKeyPair : RawReader.ecKeyPair).getPrivate();
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
