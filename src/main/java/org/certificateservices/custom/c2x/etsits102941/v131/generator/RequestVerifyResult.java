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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;

import javax.crypto.SecretKey;

/**
 * Result of a verification request messages of a signed EtsiTs102941Data message containing signed identifier and
 * header info, secret key used in response if applicable,  along with a deserialized inner message.
 */
public class RequestVerifyResult<T> extends VerifyResult<T> {

    byte[] requestHash;
    SecretKey secretKey;

    /**
     * Main constructor
     *
     * @param signAlg the algorithm used in the signature.
     * @param signerIdentifier the signerIdentifier if related object was signed, otherwise null.
     * @param headerInfo the header info object if related object was signed, otherwise null.
     * @param value the inner message data.
     */
    public RequestVerifyResult(Signature.SignatureChoices signAlg, SignerIdentifier signerIdentifier, HeaderInfo headerInfo, T value,
                               byte[] requestHash, SecretKey secretKey) {
        super(signAlg, signerIdentifier,headerInfo,value);
        this.requestHash = requestHash;
        this.secretKey = secretKey;
    }

    /**
     *
     * @return the header info object if related object was signed, otherwise null.
     */
    public byte[] getRequestHash() {
        return requestHash;
    }

    /**
     *
     * @return the secretKey to use to encrypt response with back to requester.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     *
     * @return the inner message.
     */
    public T getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "RequestVerifyResult [\n"+
                "  signerIdentifier=" + (signerIdentifier != null ? signerIdentifier.toString().replaceAll("\n", "\n  ") : "NONE") + ",\n" +
                "  headerInfo=" + (headerInfo != null ? headerInfo.toString().replaceAll("\n", "\n  ") : "NONE") +  ",\n"+
                "  value=" + getValue().toString().replaceAll("\n","\n  ") + "\n" +
                "  secretKey=" + (secretKey != null ? "EXISTS" : "NONE") +  ",\n"+
                "  requestHash=" + Hex.toHexString(requestHash) +  ",\n"+
                "]";
    }
}
