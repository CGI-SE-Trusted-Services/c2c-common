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

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;

import java.io.IOException;

/**
 * <p>
 *     EtsiTs103097Data-Encrypted-Unicast Profile. For details see section 7.2 of ETSI 102 941 v1.3.1
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs103097DataEncryptedUnicast extends EtsiTs103097DataEncrypted {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097DataEncryptedUnicast(){
        super();
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataEncryptedUnicast(Ieee1609Dot2Content content) throws IOException{
        super(content);
        validateEncryptedUnicast();
    }

    /**
     * Constructor used when encoding
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataEncryptedUnicast(int protocolVersion, Ieee1609Dot2Content content)
            throws IOException{
        super(protocolVersion,content);
        validateEncryptedUnicast();

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataEncryptedUnicast(byte[] encodedData) throws IOException{
        super(encodedData);
        validateEncryptedUnicast();
    }

    /**
     * Method to validate data against the validate encrypted unicast ASN.1 Profile.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    protected void validateEncryptedUnicast() throws IOException {

        EncryptedData encryptedData = (EncryptedData) getContent().getValue();
        if(encryptedData.getRecipients().size() != 1){
            throw new IOException("EtsiTs103097Data with profile Encrypted-Unicast must exactly one recipient.");
        }
    }

}
