/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.util;

// Source configured for Android.

/**
 * Encodes/decodes base64URL data.
 * See RFC 4648 Table 2.
 */
public class Base64URL {

    private Base64URL() {}  // No instantiation please

    /**
     * Decode base64url string.
     * <p>
     * This method <b>does not</b> accept padding or line wraps.
     * </p>
     *
     * @param base64Url Encoded data in base64url format
     * @return Decoded data as a byte array
     * @throws IllegalArgumentException
     */
    public static byte[] decode(String base64Url) {
        if (base64Url.contains("=")) {
            throw new IllegalArgumentException("Padding not allowed");
        }
        // Flaky decoder fix :(
        return decodePadded(base64Url);
     }

    /**
     * Decode base64url string.
     * <p>
     * This method accepts <i>optional</i> padding.
     * </p>
     * <p>
     * Note that line wraps are <b>not</b> permitted.
     * </p>
     * 
     * @param base64Url Encoded data in base64url format
     * @return Decoded data as a byte array
     * @throws IllegalArgumentException
     */
    public static byte[] decodePadded(String base64Url) {
        byte[] bytes = android.util.Base64.decode(base64Url, android.util.Base64.URL_SAFE);
        // Flaky decoder fix :(
        final String reencoded = encode(bytes);
        int last = reencoded.length() - 1;
        if (last >= 0 && reencoded.charAt(last) != base64Url.charAt(last)) {
            throw new IllegalArgumentException("Invalid base64 termination character");
        }
        return bytes;
    }

    /**
     * Encode byte array.
     * <p>
     * This method adds no padding or line wraps.
     * </p>
     *
     * @param byteArray Binary data
     * @return Encoded data as a base64url string
     */
    public static String encode(byte[] byteArray) {
        return android.util.Base64.encodeToString(byteArray,
                                                  android.util.Base64.URL_SAFE |
                                                    android.util.Base64.NO_PADDING |
                                                    android.util.Base64.NO_WRAP);
    }
}
