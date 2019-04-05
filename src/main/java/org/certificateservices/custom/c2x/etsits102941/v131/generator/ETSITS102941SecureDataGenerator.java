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
package org.certificateservices.custom.c2x.etsits102941.v131.generator;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

import java.io.IOException;
import java.security.SignatureException;

/**
 * ETSI TS 102 941 Specific SecureDataGenerator that creates encrypted structures using the
 * EtsiTs103097DataEncryptedUnicast profile.
 *
 * @see org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class ETSITS102941SecureDataGenerator extends ETSISecuredDataGenerator {
    /**
     * Main constructor.
     *
     * @param version       version if Ieee1609Dot2Data to generate.
     * @param cryptoManager the related crypto manager
     * @param hashAlgorithm the related hash algorithm used in messages
     * @param signAlgorithm the related sign algorithm used in messages.
     * @throws SignatureException if internal problems occurred initializing the generator.
     */
    public ETSITS102941SecureDataGenerator(int version, Ieee1609Dot2CryptoManager cryptoManager, HashAlgorithm hashAlgorithm, Signature.SignatureChoices signAlgorithm) throws SignatureException {
        super(version, cryptoManager, hashAlgorithm, signAlgorithm);
    }

    @Override
    protected Ieee1609Dot2Data newEncryptedDataStructure(byte[] encodedData) throws IOException {
        return new EtsiTs103097DataEncryptedUnicast(encodedData);
    }

    @Override
    protected Ieee1609Dot2Data newEncryptedDataStructure(int version, Ieee1609Dot2Content content) throws IOException {
        return new EtsiTs103097DataEncryptedUnicast(version,content);
    }
}
