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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;

import javax.crypto.SecretKey;

/**
 * Value Object class representing result of a SecuredDataGenerator.decrypt operation.
 * Contains the decrypted data and the decryption key used.
 *
 *  @author Philip Vendil, p.vendil@cgi.com
 */
public class DecryptResult {

    SecretKey secretKey;
    byte[] data;

    /**
     * Main constructor
     *
     * @param secretKey the secret symmetric key used to decrypt the data.
     * @param data the inner opaque data.
     */
    public DecryptResult(SecretKey secretKey, byte[] data) {
        this.secretKey = secretKey;
        this.data = data;
    }

    /**
     *
     * @return the the secret symmetric key used to decrypt the data.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
    /**
     *
     * @return the inner opaque data.
     */
    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return "DecryptAndVerifyResult [\n"+
                "  secretKey=" + (secretKey != null ? "EXISTS" : "NONE") +  ",\n"+
                "  data=" + Hex.toHexString(getData()) + "\n" +
                "]";
    }
}
