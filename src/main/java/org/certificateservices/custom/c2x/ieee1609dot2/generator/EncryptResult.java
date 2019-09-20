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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

import javax.crypto.SecretKey;

/**
 * Value Object class representing result of a SecuredDataGenerator.encrypt operation.
 * Contains the encrypted data and the encryption secret key used.
 *
 *  @author Philip Vendil, p.vendil@cgi.com
 */
public class EncryptResult {

    SecretKey secretKey;
    Ieee1609Dot2Data encryptedData;

    /**
     * Main constructor
     *
     * @param secretKey the secret symmetric key used to encrypt the data.
     * @param encryptedData the encrypted data
     */
    public EncryptResult(SecretKey secretKey, Ieee1609Dot2Data encryptedData) {
        this.secretKey = secretKey;
        this.encryptedData = encryptedData;
    }

    /**
     *
     * @return the the secret symmetric key used to encrypt the data.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
    /**
     *
     * @return the encrypted data
     */
    public Ieee1609Dot2Data getEncryptedData() {
        return encryptedData;
    }

    @Override
    public String toString() {
        return "EncryptResult [\n"+
                "  secretKey=" + (secretKey != null ? "EXISTS" : "NONE") +  ",\n"+
                "  encryptedData=" + getEncryptedData().toString().replaceAll("\n","\n  ") + "\n" +
                "]";
    }
}
