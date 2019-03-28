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

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*;

import java.io.IOException;

/**
 * <p>
 *     Signed Data profile of EtsiTs103097Data. For details see section 5.2 of ETIS 103 097 v1.3.1
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs103097DataSigned extends EtsiTs103097Data {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097DataSigned(){
        super();
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IllegalArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataSigned(Ieee1609Dot2Content content) throws IllegalArgumentException{
        super(content);
        validateSigned();
    }

    /**
     * Constructor used when encoding
     * @throws IllegalArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataSigned(int protocolVersion, Ieee1609Dot2Content content) throws IllegalArgumentException{
        super(protocolVersion,content);
        validateSigned();

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if communication problems occurred during serialization.
     * @throws IllegalArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataSigned(byte[] encodedData) throws IOException, IllegalArgumentException{
        super(encodedData);
        validateSigned();
    }

    protected void validateSigned() throws IllegalArgumentException{
        if(getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData) {
            throw new IllegalArgumentException("EtsiTs103097Data with profile Signed must have content of type: signedData");
        }
        SignedData signedData = (SignedData) getContent().getValue();
        if(signedData.getTbsData() == null){
            throw new IllegalArgumentException("Invalid EtsiTs103097Data with profile Signed, signed data must have tbsData set.");
        }

        SignedDataPayload payload = signedData.getTbsData().getPayload();
        if(payload.getData() == null) {
            throw new IllegalArgumentException("Invalid EtsiTs103097Data with profile Signed must have payload with data field set.");
        }
        Ieee1609Dot2Data ieee1609Dot2Data = payload.getData();
        if(ieee1609Dot2Data.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData) {
            throw new IllegalArgumentException("Invalid EtsiTs103097Data with profile Signed must have payload data field of type unsecuredData.");
        }
    }

}
