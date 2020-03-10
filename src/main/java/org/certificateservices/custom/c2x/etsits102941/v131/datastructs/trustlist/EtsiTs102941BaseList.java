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

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;

import java.io.IOException;

/**
 * <p>
 *     Specific EtsiTs103097DataSigned extension class with an in-common toString method for EtsiTs102941CRL
 *     and EtsiTs102941CTL
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public abstract class EtsiTs102941BaseList extends EtsiTs103097DataSigned {

    /**
     * Constructor used when decoding
     */
    public EtsiTs102941BaseList(){
        super();
    }

    /**
     * Constructor when converting a EtsiTs103097DataSigned to EtsiTs102941CRL
     * @throws IOException if communication problems occurred during serialization.
     */
    public EtsiTs102941BaseList(EtsiTs103097DataSigned etsiTs103097DataSigned) throws IOException{
        super(etsiTs103097DataSigned.getProtocolVersion(),etsiTs103097DataSigned.getContent());
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IOException if communication problems occurred during serialization.
     */
    public EtsiTs102941BaseList(Ieee1609Dot2Content content) throws IOException{
        super(content);
    }

    /**
     * Constructor used when encoding
     * @throws IOException if communication problems occurred during serialization.
     */
    public EtsiTs102941BaseList(int protocolVersion, Ieee1609Dot2Content content) throws IOException{
        super(protocolVersion,content);
    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if communication problems occurred during serialization.
     */
    public EtsiTs102941BaseList(byte[] encodedData) throws IOException{
        super(encodedData);
        validateSigned();
    }

    @Override
    public String toString() {
        try {
            Ieee1609Dot2Data innerData = ((SignedData) getContent().getValue()).getTbsData().getPayload().getData();
            String innerDataString = "NO DATA";
            if (innerData != null) {
                Opaque opaque = (Opaque) innerData.getContent().getValue();
                EtsiTs102941Data toBeSignedRcaCtl = new EtsiTs102941Data(opaque.getData());

                innerDataString = toBeSignedRcaCtl.toString().replaceAll("\n", "\n              ") + "\n";
            }
            String outerData = super.toString().replace("EtsiTs103097Data ", "EtsiTs103097DataSigned ");
            String[] outerDataLines = outerData.split("\n");
            StringBuilder sb = new StringBuilder();
            for (String line : outerDataLines) {
                if (!line.contains("unsecuredData=")) {
                    sb.append(line).append("\n");
                } else {
                    sb.append("              " + innerDataString);
                }
            }

            return sb.toString();
        }catch (IOException e){
            return "Invalid encoding of EtsiTs102941CRL: " + e.getMessage();
        }
    }

}
