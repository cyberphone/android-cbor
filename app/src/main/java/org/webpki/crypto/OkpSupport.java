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

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;

public class OkpSupport {
    public static byte[] public2RawOkpKey(PublicKey publicKey, KeyAlgorithms keyAlgorithm)
    throws IOException {
        throw new IOException("Feature not yet available in Android");
    }
    public static PublicKey raw2PublicOkpKey(byte[] x, KeyAlgorithms keyAlgorithm) 
    throws IOException {
        throw new IOException("Feature not yet available in Android");
    }

    public static byte[] private2RawOkpKey(PrivateKey privateKey, KeyAlgorithms keyAlgorithm) 
    throws IOException {
        throw new IOException("Feature not yet available in Android");
    }
    public static PrivateKey raw2PrivateOkpKey(byte[] d, KeyAlgorithms keyAlgorithm)
    throws IOException {
        throw new IOException("Feature not yet available in Android");
    }
    public static KeyAlgorithms getOkpKeyAlgorithm(Key key) {
        throw new RuntimeException("Feature not yet available in Android");
    }
}
