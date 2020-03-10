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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;

import java.io.IOException;

/**
 * <p>
 *    Specific EtsiTs103097DataSigned extension class for EtsiTs102941CRL with help
 *    method for better pretty printing toString()
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs102941CTL extends EtsiTs102941BaseList {

    /**
     * Constructor used when decoding
     */
    public EtsiTs102941CTL(){
        super();
    }

    /**
     * Constructor when converting a EtsiTs103097DataSigned to EtsiTs102941CTL
     */
    public EtsiTs102941CTL(EtsiTs103097DataSigned etsiTs103097DataSigned)throws IOException{
        super(etsiTs103097DataSigned.getProtocolVersion(),etsiTs103097DataSigned.getContent());
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs102941CTL(Ieee1609Dot2Content content) throws IOException{
        super(content);
    }

    /**
     * Constructor used when encoding
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs102941CTL(int protocolVersion, Ieee1609Dot2Content content) throws IOException{
        super(protocolVersion,content);

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if communication problems occurred during serialization.
     */
    public EtsiTs102941CTL(byte[] encodedData) throws IOException{
        super(encodedData);
    }


}
