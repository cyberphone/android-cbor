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
package org.webpki.cbor;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.X509SignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for creating CBOR X509 signatures.
 * <p>
 * See {@link CBORSigner} for details.
 * </p>
 * <p> 
 * Note that X509 signatures do not permit the use of a keyId.
 * </p>
 */
public class CBORX509Signer extends CBORSigner {

    X509SignerInterface signer;
    
    /**
     * Initializes a signer with an external interface.
     * 
     * @param signer Custom signer
     * @throws GeneralSecurityException 
     * @throws IOException 
     */
    public CBORX509Signer(X509SignerInterface signer) throws IOException,
                                                             GeneralSecurityException {
        this.signer = signer;
    }
    
    /**
     * Initializes an X509 signer with a private key.
     * <p>
     * The signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * </p>
     * @param privateKey Signature key
     * @param certificatePath A matching non-null certificate path
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORX509Signer(PrivateKey privateKey,
                          X509Certificate[] certificatePath) throws IOException, 
                                                                    GeneralSecurityException {
        this(privateKey, 
             certificatePath, 
             KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }

    /**
     * Initializes an X509 signer with a private key.
     * 
     * @param privateKey Signature key
     * @param certificatePath A matching non-null certificate path
     * @param algorithm Signature algorithm
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORX509Signer(PrivateKey privateKey,
                          X509Certificate[] certificatePath,
                          AsymSignatureAlgorithms algorithm) throws IOException,
                                                                    GeneralSecurityException {
        signer = new X509SignerInterface() {

            @Override
            public byte[] signData(byte[] dataToBeSigned) throws IOException,
                                                                 GeneralSecurityException {
                return CBORCryptoUtils.asymKeySignatureGeneration(privateKey,
                                                                  algorithm,
                                                                  dataToBeSigned, 
                                                                  provider);
            }

            @Override
            public X509Certificate[] getCertificatePath() throws IOException, 
                                                                 GeneralSecurityException {
                return certificatePath;
            }

            @Override
            public AsymSignatureAlgorithms getAlgorithm() {
                return algorithm;
            }
            
        };
    }

    @Override
    byte[] coreSigner(byte[] dataToBeSigned) throws IOException, GeneralSecurityException {
        return signer.signData(dataToBeSigned);
    }
    
    @Override
    void additionalItems(CBORMap signatureObject) 
            throws IOException, GeneralSecurityException {
        // X509 signatures mandate a certificate path.
        signatureObject.setObject(CERT_PATH_LABEL, CBORCryptoUtils.encodeCertificateArray(
                signer.getCertificatePath()));
        // Key IDs are not permitted.
        CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
    }

    @Override
    SignatureAlgorithms getAlgorithm() throws IOException, GeneralSecurityException {
        return signer.getAlgorithm();
    }
}
