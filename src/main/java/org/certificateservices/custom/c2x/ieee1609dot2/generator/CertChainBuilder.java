/************************************************************************
 *                                                                       *
 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.generator;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Class containing methods to build a certificate chain from a set of known certificates and a trust store
 * of root certificates.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class CertChainBuilder {


    /**
     * Help method to build a certificate chain from a signerId and two collections of known certificates and trust store.
     *
     * @throws BadArgumentException if chain couldn't be built.
     */
    public static Certificate[] buildChain(CryptoManager cryptoManager, HashedId8 signerId, CertStore signedDataStore, CertStore certStore, CertStore trustStore) throws BadArgumentException, NoSuchAlgorithmException, IOException {
        List<Certificate> foundCerts = new ArrayList<>();
        // find first cert
        Certificate firstCert;
        firstCert = findFromStores(cryptoManager,signerId, signedDataStore, certStore, trustStore);

        if(firstCert == null){
            throw new BadArgumentException("Error no certificate found in certstore for id : " + signerId);
        }
        foundCerts.add(firstCert);
        Certificate nextCert = firstCert;
        while(nextCert.getIssuer().getType() != IssuerIdentifier.IssuerIdentifierChoices.self){
            HashedId8 issuerId = (HashedId8) nextCert.getIssuer().getValue();
            nextCert = findFromStores(cryptoManager, issuerId, signedDataStore, certStore, trustStore);
            if(nextCert == null){
                throw new BadArgumentException("Error no certificate found in certstore for id : " + signerId);
            }
            foundCerts.add(nextCert);
        }

        HashedId8 trustAncor = getCertID(cryptoManager,foundCerts.get(foundCerts.size() -1));
        if(trustStore.get(trustAncor) == null){
            throw new BadArgumentException("Error last certificate in chain wasn't a trust anchor: " + trustAncor);
        }

        return foundCerts.toArray(new Certificate[foundCerts.size()]);
    }


    /**
     * Help method that tries to first find the certificate from cert store and then in trust store if not found.
     * It also checks that trust store certificate is an explicit certificate.
     * @return the found certificate or null if no certificate found in any of the stores.
     * @throws if found an implicit certificate in trust store.
     */
    protected static Certificate findFromStores(CryptoManager cryptoManager, HashedId8 certId, CertStore signedDataStore, CertStore certStore, CertStore trustStore) throws BadArgumentException{
        Certificate retval = (Certificate) signedDataStore.get(certId);
        if(retval != null){
            return retval;
        }

        retval = (Certificate) certStore.get(certId);
        if(retval != null){
            return retval;
        }

        retval = (Certificate) trustStore.get(certId);
        if(retval != null && retval.getType() == CertificateType.implicit){
            throw new BadArgumentException("Error trust anchor cannot be an implicit certificate");
        }
        return retval;

    }

    /**
     * Help method that generated a HashedId8 cert id from a certificate.
     */
    public static HashedId8 getCertID(CryptoManager cryptoManager, Certificate cert) throws BadArgumentException, NoSuchAlgorithmException, IOException{
        HashAlgorithm hashAlgorithm = HashAlgorithm.sha256;
        if(cert.getType() == CertificateType.explicit ){
            VerificationKeyIndicator vki = cert.getToBeSigned().getVerifyKeyIndicator();
            PublicVerificationKey pvk = (PublicVerificationKey) vki.getValue();
            if(pvk.getValue() instanceof EccP384CurvePoint){
                hashAlgorithm = HashAlgorithm.sha384;
            }
        }

        return new HashedId8(cryptoManager.digest(cert.getEncoded(),hashAlgorithm));
    }
}
