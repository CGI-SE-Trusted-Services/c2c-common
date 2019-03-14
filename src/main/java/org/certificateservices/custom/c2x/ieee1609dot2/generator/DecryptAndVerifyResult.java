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

/**
 * Value Object class representing result of a SecuredDataGenerator.decryptAndVerifySignedData operation.
 * Contains the inner opaque data and optional headerInfo if object was signed.
 *
 *  @author Philip Vendil, p.vendil@cgi.com
 */
public class DecryptAndVerifyResult {

    SignerIdentifier signerIdentifier;
    HeaderInfo headerInfo;
    byte[] data;

    /**
     * Main constructor
     *
     * @param signerIdentifier the signerIdentifier if related object was signed, otherwise null.
     * @param headerInfo the header info object if related object was signed, otherwise null.
     * @param data the inner opaque data.
     */
    public DecryptAndVerifyResult(SignerIdentifier signerIdentifier, HeaderInfo headerInfo, byte[] data) {
        this.signerIdentifier = signerIdentifier;
        this.headerInfo = headerInfo;
        this.data = data;
    }

    /**
     *
     * @return the signerIdentifier if related object was signed, otherwise null.
     */
    public SignerIdentifier getSignerIdentifier() {
        return signerIdentifier;
    }

    /**
     *
     * @return the header info object if related object was signed, otherwise null.
     */
    public HeaderInfo getHeaderInfo() {
        return headerInfo;
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
                "  signerIdentifier=" + (signerIdentifier != null ? signerIdentifier.toString().replaceAll("\n", "\n  ") : "NONE") + ",\n" +
                "  headerInfo=" + (headerInfo != null ? headerInfo.toString().replaceAll("\n", "\n  ") : "NONE") +  ",\n"+
                "  data=" + Hex.toHexString(getData()) + "\n" +
                "]";
    }
}
