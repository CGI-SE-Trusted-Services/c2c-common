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
package org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*;

import java.io.IOException;

/**
 * <p>
 *     Signed With External Payload Data profile of EtsiTs103097Data. For details see section 5.2 of ETIS 103 097 v1.3.1
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs103097DataSignedExternalPayload extends EtsiTs103097Data {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097DataSignedExternalPayload(){
        super();
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataSignedExternalPayload(Ieee1609Dot2Content content) throws IOException{
        super(content);
        validateSignedExternalPayload();
    }

    /**
     * Constructor used when encoding
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataSignedExternalPayload(int protocolVersion, Ieee1609Dot2Content content) throws IOException {
        super(protocolVersion,content);
        validateSignedExternalPayload();

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if communication problems occurred during serialization.
     * @throws BadArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataSignedExternalPayload(byte[] encodedData) throws IOException{
        super(encodedData);
        validateSignedExternalPayload();
    }

    protected void validateSignedExternalPayload() throws IOException{
        if(getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData) {
            throw new IOException("EtsiTs103097Data with profile SignedExternalPayload must have content of type: signedData");
        }
        SignedData signedData = (SignedData) getContent().getValue();
        if(signedData.getTbsData() == null){
            throw new IOException("Invalid EtsiTs103097Data with profile SignedExternalPayload, signed data must have tbsData set.");
        }

        SignedDataPayload payload = signedData.getTbsData().getPayload();
        if(payload.getExtDataHash() == null) {
            throw new IOException("Invalid EtsiTs103097Data with profile SignedExternalPayload must have payload with extDataHash field set.");
        }
        HashedData hashedData = payload.getExtDataHash();
        if(hashedData.getType() != HashedData.HashedDataChoices.sha256HashedData) {
            throw new IOException("Invalid EtsiTs103097Data with profile SignedExternalPayload must have extDataHash of type sha256HashedData.");
        }
    }

}
