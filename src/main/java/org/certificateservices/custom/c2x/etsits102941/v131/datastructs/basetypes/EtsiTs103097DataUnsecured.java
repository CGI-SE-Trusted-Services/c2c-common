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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097Data;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;

import java.io.IOException;

/**
 * <p>
 *     EtsiTs103097Data-Unsecured Profile. For details see section 7.2 of ETSI 102 941 v1.3.1
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs103097DataUnsecured extends EtsiTs103097Data {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097DataUnsecured(){
        super();
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataUnsecured(Ieee1609Dot2Content content) throws IOException{
        super(content);
        validateUnsecured();
    }

    /**
     * Constructor used when encoding
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataUnsecured(int protocolVersion, Ieee1609Dot2Content content) throws IOException{
        super(protocolVersion,content);
        validateUnsecured();

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if communication problems occurred during serialization.
     */
    public EtsiTs103097DataUnsecured(byte[] encodedData) throws IOException{
        super(encodedData);
        validateUnsecured();
    }

    protected void validateUnsecured() throws IOException{
        if(getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData){
            throw new IOException("EtsiTs103097Data with profile Unseured must be of type unsecured.");
        }
    }

}
