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
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import javax.crypto.SecretKey;

/**
 * Value Object class representing result of a SecuredDataGenerator.decrypt operation.
 * Contains the decrypted data and the decryption key used.
 *
 *  @author Philip Vendil, p.vendil@cgi.com
 */
public class DecryptResult {

    Receiver receiver;
    SecretKey secretKey;
    byte[] data;

    /**
     * Main constructor
     *
     * @param receiver the related receiver of the message
     * @param secretKey the secret symmetric key used to decrypt the data.
     * @param data the inner opaque data.
     */
    public DecryptResult(Receiver receiver, SecretKey secretKey, byte[] data) {
        this.receiver = receiver;
        this.secretKey = secretKey;
        this.data = data;
    }


    /**
     * @return the receiver of the message
     */
    public Receiver getReceiver(){ return receiver; }
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
                "  receiver=" + (receiver != null ? "EXISTS" : "NONE") +  ",\n"+
                "  secretKey=" + (secretKey != null ? "EXISTS" : "NONE") +  ",\n"+
                "  data=" + Hex.toHexString(getData()) + "\n" +
                "]";
    }
}
