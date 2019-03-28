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
package org.certificateservices.custom.c2x.etsits102941.v121.generator;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;

/**
 * Result of a verification of a signed EtsiTs102941Data message containing signed identifier and
 * header info, secret key used in response if applicable,  along with a deserialized inner message.
 */
public class VerifyResult<T> {

    SignerIdentifier signerIdentifier;
    HeaderInfo headerInfo;
    T value;

    /**
     * Main constructor
     *
     * @param signerIdentifier the signerIdentifier if related object was signed, otherwise null.
     * @param headerInfo the header info object if related object was signed, otherwise null.
     * @param value the inner message data.
     */
    public VerifyResult(SignerIdentifier signerIdentifier, HeaderInfo headerInfo, T value) {
        this.signerIdentifier = signerIdentifier;
        this.headerInfo = headerInfo;
        this.value = value;
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
     * @return the inner message.
     */
    public T getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "VerifyResult [\n"+
                "  signerIdentifier=" + (signerIdentifier != null ? signerIdentifier.toString().replaceAll("\n", "\n  ") : "NONE") + ",\n" +
                "  headerInfo=" + (headerInfo != null ? headerInfo.toString().replaceAll("\n", "\n  ") : "NONE") +  ",\n"+
                "  value=" + getValue().toString().replaceAll("\n","\n  ") + "\n" +
                "]";
    }
}
