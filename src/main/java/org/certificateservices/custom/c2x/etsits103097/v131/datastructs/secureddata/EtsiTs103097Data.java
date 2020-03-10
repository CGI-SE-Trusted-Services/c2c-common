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

import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;

import java.io.IOException;
import java.util.List;

/**
 * <p>
 *     A secure data structure shall be of type EtsiTs103097Data as defined in annex A, which corresponds to a
 * Ieee1609Dot2Data as defined in IEEE Std 1609.2 [1] clause 6.3.2, with the constraints defined in this clause, in
 * clause 5.2 and in clause 5.3.
 * </p>
 * <p>
 *     The type Ieee1609Dot2Data shall support the following options in the component content:
 *     <ul>
 *         <li>The option unsecuredData shall be used to encapsulate an unsecured data structure.</li>
 *         <li>The option signedData, corresponding to the type SignedData as defined in IEEE Std 1609.2 [1]
 * clause 6.3.4, shall be used to transfer a data structure with a signature.</li>
 *         <li>The option encryptedData, corresponding to the type EncryptedData as defined in IEEE
 * Std 1609.2 [1] clause 6.3.30, shall be used to transfer an encrypted data structure.</li>
 *     </ul>
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class EtsiTs103097Data extends Ieee1609Dot2Data {

    /**
     * Constructor used when decoding
     */
    public EtsiTs103097Data(){
        super();
    }

    /**
     * Constructor used when encoding using default protocol version.
     * @throws BadArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097Data(Ieee1609Dot2Content content) throws IOException{
        super(content);
        validate();
    }

    /**
     * Constructor used when encoding
     * @throws BadArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097Data(int protocolVersion, Ieee1609Dot2Content content) throws IOException {
        super(protocolVersion,content);
        validate();

    }

    /**
     * Constructor decoding a Ieee1609Dot2Data from an encoded byte array.
     * @param encodedData byte array encoding of the Ieee1609Dot2Data.
     * @throws IOException   if communication problems occurred during serialization.
     * @throws BadArgumentException if encoded data was invalid according to ASN1 schema.
     */
    public EtsiTs103097Data(byte[] encodedData) throws IOException{
        super(encodedData);
        validate();
    }

    protected void validate() throws IOException{
        if(getContent().getType() == Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData){
            SignedData signedData = (SignedData) getContent().getValue();
            if(signedData.getTbsData() == null){
                throw new IOException("Invalid EtsiTs103097Data, signed data must have tbsData set.");
            }
            if(signedData.getTbsData().getHeaderInfo() == null){
                throw new IOException("Invalid EtsiTs103097Data, signed data tbsData must have headerInfo set.");
            }
            if(signedData.getTbsData().getHeaderInfo().getGenerationTime() == null){
                throw new IOException("Invalid EtsiTs103097Data, signed data tbsData headerInfo must have generationTime set.");
            }
            if(signedData.getTbsData().getHeaderInfo().getGenerationTime() == null){
                throw new IOException("Invalid EtsiTs103097Data, signed data tbsData headerInfo must have generationTime set.");
            }
            if(signedData.getTbsData().getHeaderInfo().getP2pcdLearningRequest() != null){
                throw new IOException("Invalid EtsiTs103097Data, signed data tbsData headerInfo cannot have p2pcdLearningRequest set.");
            }
            if(signedData.getTbsData().getHeaderInfo().getMissingCrlIdentifier() != null){
                throw new IOException("Invalid EtsiTs103097Data, signed data tbsData headerInfo cannot have missingCrlIdentifier set.");
            }
            if(signedData.getSigner().getType() == SignerIdentifier.SignerIdentifierChoices.certificate) {
                SequenceOfCertificate certificates = (SequenceOfCertificate) signedData.getSigner().getValue();
                if (certificates.size() != 1) {
                    throw new IOException("Invalid EtsiTs103097Data, signed data signer certificate sequence must be of size 1.");
                }
            }
        }
        if(getContent().getType() == Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData){
            EncryptedData encryptedData = (EncryptedData) getContent().getValue();
            if(encryptedData.getRecipients() != null){
                List<COEREncodable> recipientInfos = encryptedData.getRecipients().getSequenceValuesAsList();
                for(COEREncodable next : recipientInfos){
                    RecipientInfo recipientInfo = (RecipientInfo) next;
                    if(recipientInfo.getType() == RecipientInfo.RecipientInfoChoices.symmRecipInfo ||
                            recipientInfo.getType() == RecipientInfo.RecipientInfoChoices.rekRecipInfo){
                        throw new IOException("Invalid EtsiTs103097Data, encrypted data recipient cannot be of type: " + recipientInfo.getType());
                    }
                }
            }
        }
        if(getContent().getType() == Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedCertificateRequest){
            throw new IOException("Invalid EtsiTs103097Data cannot have content of type signedCertificateRequest");
        }
    }

    @Override
    public String toString(){
        return super.toString().replace("Ieee1609Dot2Data ", "EtsiTs103097Data ").replace(" Certificate ", " EtsiTs103097Certificate ").replace("[Certificate ", "[EtsiTs103097Certificate ");
    }

}
