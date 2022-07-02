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
import java.io.ByteArrayInputStream;

import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

import java.security.GeneralSecurityException;

/**
 * X509 related operations.
 * 
 * Source configured for the free-standing Android JSON library.
 */
public class CertificateUtil {

    private CertificateUtil() {}  // No instantiation please

    public static X509Certificate[] checkCertificatePath(X509Certificate[] certificatePath) 
            throws IOException, GeneralSecurityException {
        X509Certificate signedCertificate = certificatePath[0];
        int i = 0;
        while (++i < certificatePath.length) {
            X509Certificate signerCertificate = certificatePath[i];
            String issuer = signedCertificate.getIssuerX500Principal().getName();
            String subject = signerCertificate.getSubjectX500Principal().getName();
            if (!issuer.equals(subject)) {
                throw new IOException("Path issuer order error, '" + 
                                      issuer + "' versus '" + subject + "'");
            }
            signedCertificate.verify(signerCertificate.getPublicKey());
            signedCertificate = signerCertificate;
        }
        return certificatePath;
    }

    public static X509Certificate getCertificateFromBlob(byte[] encoded)
            throws IOException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
    }

    public static X509Certificate[] makeCertificatePath(List<byte[]> certificateBlobs)
            throws IOException, GeneralSecurityException {
        ArrayList<X509Certificate> certificates = new ArrayList<>();
        for (byte[] certificateBlob : certificateBlobs) {
            certificates.add(getCertificateFromBlob(certificateBlob));
        }
        return checkCertificatePath(certificates.toArray(new X509Certificate[0]));
    }
}
