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
package org.certificateservices.custom.c2x.etsits102941.v131.validator;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.MapCertStore;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.CertChainBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Base class containing in common help methods between CRL and CTL Validator classes.
 *
 * @author Philip Vendil
 */
public abstract class BaseEtsiTs102941ListValidator {

    protected Ieee1609Dot2CryptoManager cryptoManager;
    protected CertChainBuilder certChainBuilder;
    protected CertStore emptyStore = new MapCertStore(new HashMap<>());

    protected BaseEtsiTs102941ListValidator(Ieee1609Dot2CryptoManager cryptoManager){
        this.cryptoManager = cryptoManager;
    }

    /**
     * Help method to generate HashedId8 of a certificate.
     * @param certificate the certificate to generate Id for.
     * @return a newly generated HashedId8 certificate Id
     * @throws InvalidCertificateException if encoding problems occurred.
     * @throws NoSuchAlgorithmException if no SHA-256 digest algorithm was found
     */
    protected HashedId8 toHashedId8(org.certificateservices.custom.c2x.common.Certificate certificate)
            throws InvalidCertificateException, NoSuchAlgorithmException {
        try {
            return certificate.asHashedId8(cryptoManager);
        } catch (IOException e) {
            throw new InvalidCertificateException("Error generating HashedId8 of certificate: " + e.getMessage());
        }
    }

    /**
     * Help method to get the SignerIdentifier element from the signData structure.
     */
    protected SignerIdentifier findSignerIdentifier(EtsiTs103097DataSigned signedData) throws BadArgumentException {
        if(signedData.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData){
            throw new BadArgumentException("Only signed Ieee1609Dot2Data can verified");
        }

        SignedData sd = (SignedData) signedData.getContent().getValue();
        if(sd.getTbsData().getPayload().getData() == null){
            throw new BadArgumentException("Error no enveloped data found in Signed Payload");
        }
        return sd.getSigner();
    }

    /**
     * Help method to get a HashedId8 cert id from a SignerIdentifier.
     */
    protected HashedId8 getSignerId(SignerIdentifier signer) throws BadArgumentException, NoSuchAlgorithmException,
            IOException {
        if(signer.getType() == SignerIdentifier.SignerIdentifierChoices.digest){
            return (HashedId8) signer.getValue();
        }
        if(signer.getType() == SignerIdentifier.SignerIdentifierChoices.self){
            throw new BadArgumentException("SignedData cannot be self signed");
        }
        SequenceOfCertificate sc = (SequenceOfCertificate) signer.getValue();
        return CertChainBuilder.getCertID(cryptoManager,(Certificate) sc.getSequenceValues()[0]);
    }
}
