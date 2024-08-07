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
package org.webpki.cbor;

import org.webpki.crypto.ContentEncryptionAlgorithms;

/**
 * Class for symmetric key decryption.
 */
public class CBORSymKeyDecrypter extends CBORDecrypter<CBORSymKeyDecrypter> {
    
    /**
     * Interface for dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Lookup of secret decryption key.
         * <p>
         * An implementation is supposed to throw an exception if it
         * does not find a matching key or if the supplied algorithm does
         * not meet the policy.
         * </p>
         * 
         * @param optionalKeyId Optional key Id found in the encryption object
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Decryption key
         */
        byte[] locate(CBORObject optionalKeyId, 
                      ContentEncryptionAlgorithms contentEncryptionAlgorithm);
    }
    
    KeyLocator keyLocator;
    
    /**
     * Creates a decrypter object with a secret key.
     * <p>
     * This constructor presumes that the decryption key is given by the context.
     * </p>
     * 
     * @param secretKey Decryption key
     */
    public CBORSymKeyDecrypter(byte[] secretKey) {
        this((optionalKeyId, contentEncryptionAlgorithm) -> secretKey);
    }

    /**
     * Creates a decrypter object with a key locator.
     * 
     * @param keyLocator DecrypterImpl implementation
     */
    public CBORSymKeyDecrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }
    
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) {
        return keyLocator.locate(optionalKeyId, contentEncryptionAlgorithm);
    }

    @Override
    CBORSymKeyDecrypter getThis() {
        return this;
    }
}
