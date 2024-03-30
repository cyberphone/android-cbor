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
package org.webpki.crypto;

import java.io.ByteArrayInputStream;

import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

import java.security.GeneralSecurityException;

// Source configured for the free-standing Android CBOR/JSON libraries.

/**
 * X509 certificate related operations.
 */ 
public class CertificateUtil {

    private CertificateUtil() {}  // No instantiation please

    static boolean verifyCertificate(X509Certificate child, X509Certificate parent) {
        try {
            child.verify(parent.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static byte[] getBlobFromCertificate(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }
    
    public static X509Certificate[] checkCertificatePath(X509Certificate[] certificatePath) {
        X509Certificate signedCertificate = certificatePath[0];
        int i = 0;
        while (++i < certificatePath.length) {
            X509Certificate signerCertificate = certificatePath[i];
            String issuer = signedCertificate.getIssuerX500Principal().getName();
            String subject = signerCertificate.getSubjectX500Principal().getName();
            if (!issuer.equals(subject) ||
                !verifyCertificate(signedCertificate, signerCertificate)) {
                throw new CryptoException("Path issuer order error, '" + 
                                          issuer + "' versus '" + subject + "'");
            }
            signedCertificate = signerCertificate;
        }
        return certificatePath;
    }

    public static X509Certificate getCertificateFromBlob(byte[] encoded) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    public static X509Certificate[] makeCertificatePath(List<byte[]> certificateBlobs) {
        ArrayList<X509Certificate> certificates = new ArrayList<>();
        for (byte[] certificateBlob : certificateBlobs) {
            certificates.add(getCertificateFromBlob(certificateBlob));
        }
        return checkCertificatePath(certificates.toArray(new X509Certificate[0]));
    }
}
