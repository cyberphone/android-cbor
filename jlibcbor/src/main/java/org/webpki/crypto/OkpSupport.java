/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
package org.webpki.crypto;

import androidx.annotation.RequiresApi;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;

import java.security.interfaces.XECKey;
import java.security.interfaces.EdECKey;

import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.HashMap;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;

// Source configured for Android 13+

/**
 * Support methods for "OKP" [<a href='https://datatracker.ietf.org/doc/html/rfc8037'>RFC&nbsp;8037</a>].
 */ 
public class OkpSupport {
    
    private OkpSupport() {}
    
    static final HashMap<KeyAlgorithms,Integer> okpKeyLength = new HashMap<>();

    static {
        okpKeyLength.put(KeyAlgorithms.ED25519, 32);
        okpKeyLength.put(KeyAlgorithms.ED448,   57);
        okpKeyLength.put(KeyAlgorithms.X25519,  32);
        okpKeyLength.put(KeyAlgorithms.X448,    56);
    }

    static final HashMap<KeyAlgorithms,byte[]> pubKeyPrefix = new HashMap<>();
    
    static {
        pubKeyPrefix.put(KeyAlgorithms.ED25519, 
                         HexaDecimal.decode("302a300506032b6570032100"));
        pubKeyPrefix.put(KeyAlgorithms.ED448,
                         HexaDecimal.decode("3043300506032b6571033a00"));
        pubKeyPrefix.put(KeyAlgorithms.X25519,
                         HexaDecimal.decode("302a300506032b656e032100"));
        pubKeyPrefix.put(KeyAlgorithms.X448,
                         HexaDecimal.decode("3042300506032b656f033900"));
    }

    static final byte PRIV_KEY_LENGTH = 15;

    static final HashMap<KeyAlgorithms,byte[]> privKeyPrefix = new HashMap<>();

    static {
        privKeyPrefix.put(KeyAlgorithms.ED25519, 
                          HexaDecimal.decode("302e020100300506032b657004220420"));
        privKeyPrefix.put(KeyAlgorithms.ED448,
                          HexaDecimal.decode("3047020100300506032b6571043b0439"));
        privKeyPrefix.put(KeyAlgorithms.X25519,
                          HexaDecimal.decode("302e020100300506032b656e04220420"));
        privKeyPrefix.put(KeyAlgorithms.X448,
                          HexaDecimal.decode("3046020100300506032b656f043a0438"));
    }

    public static byte[] public2RawKey(PublicKey publicKey, KeyAlgorithms keyAlgorithm)
            throws IOException {
        byte[] encoded = publicKey.getEncoded();
        int prefixLength = pubKeyPrefix.get(keyAlgorithm).length;
        if (okpKeyLength.get(keyAlgorithm) != encoded.length - prefixLength) {
            throw new IOException("Wrong public key length for: " + keyAlgorithm.toString());
        }
        byte[] rawKey = new byte[encoded.length - prefixLength];
        System.arraycopy(encoded, prefixLength, rawKey, 0, rawKey.length);
        return rawKey;
    }

    public static PublicKey raw2PublicKey(byte[] x, KeyAlgorithms keyAlgorithm) 
            throws IOException, GeneralSecurityException {
        if (okpKeyLength.get(keyAlgorithm) != x.length) {
            throw new IOException("Wrong public key length for: " + keyAlgorithm.toString());
        }
        return KeyFactory.getInstance(keyAlgorithm.getJceName())
                .generatePublic(
                        new X509EncodedKeySpec(
                                ArrayUtil.add(pubKeyPrefix.get(keyAlgorithm), x)));
    }

    public static byte[] private2RawKey(PrivateKey privateKey, KeyAlgorithms keyAlgorithm) 
            throws IOException {
        byte[] encoded = privateKey.getEncoded();
        int keyLength = okpKeyLength.get(keyAlgorithm);
        byte[] prefix = privKeyPrefix.get(keyAlgorithm);
        if (encoded.length <= prefix.length || encoded[PRIV_KEY_LENGTH] != keyLength) {
            throw new IOException("Wrong private key length for: " + keyAlgorithm.toString());
        }
        byte[] rawKey = new byte[keyLength];
        System.arraycopy(encoded, prefix.length, rawKey, 0, keyLength);
        return rawKey;
    }

    public static PrivateKey raw2PrivateKey(byte[] d, KeyAlgorithms keyAlgorithm)
            throws IOException, GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm.getJceName());
        if (okpKeyLength.get(keyAlgorithm) != d.length) {
            throw new IOException("Wrong private key length for: " + keyAlgorithm.toString());
        }
        byte[] pkcs8 = ArrayUtil.add(privKeyPrefix.get(keyAlgorithm), d);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    @RequiresApi(api = 33)
    public static KeyAlgorithms getKeyAlgorithm(Key key) {
        if (key instanceof XECKey) {
            return KeyAlgorithms.getKeyAlgorithmFromId(
                    ((NamedParameterSpec)((XECKey)key).getParams()).getName(),
                    AlgorithmPreferences.JOSE);
        }
        if (key instanceof EdECKey) {
            return KeyAlgorithms.getKeyAlgorithmFromId(
                    ((EdECKey)key).getParams().getName(),
                    AlgorithmPreferences.JOSE);
        }
        // Saturn ugly fix while waiting for for EdDSA support.
        if (key.getAlgorithm().equals("1.3.101.112")) {
            return KeyAlgorithms.ED25519;
        }
        throw new IllegalArgumentException("Unknown OKP key type: " + key.getClass().getName());
    }
}