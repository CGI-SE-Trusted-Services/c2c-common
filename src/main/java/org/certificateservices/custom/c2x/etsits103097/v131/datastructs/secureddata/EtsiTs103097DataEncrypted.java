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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;

import java.io.IOException;

/**
 * <p>
 *     Encrypted Data profile of EtsiTs103097Data. For details see section 5.3 of ETIS 103 097 v1.3.1
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs103097DataEncrypted extends EtsiTs103097Data {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097DataEncrypted(){
        super();
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataEncrypted(Ieee1609Dot2Content content) throws IOException{
        super(content);
        validateEncrypted();
    }

    /**
     * Constructor used when encoding
     * @throws IOException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataEncrypted(int protocolVersion, Ieee1609Dot2Content content) throws IOException {
        super(protocolVersion,content);
        validateEncrypted();

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097DataEncrypted(byte[] encodedData) throws IOException{
        super(encodedData);
        validateEncrypted();
    }

    protected void validateEncrypted() throws IOException{
        if(getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData) {
            throw new IOException("EtsiTs103097Data with profile Encrypted must have content of type: encryptedData");
        }
        EncryptedData encryptedData = (EncryptedData) getContent().getValue();
        if(encryptedData.getCipherText().getType() != SymmetricCiphertext.SymmetricCiphertextChoices.aes128ccm){
            throw new IOException("EtsiTs103097Data with profile Encrypted must have cipherText of type: aes128ccm");
        }
    }

}
