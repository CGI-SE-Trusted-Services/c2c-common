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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EciesP256EncryptedKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo

import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genEncryptedData
import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genSignedData
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData

/**
 * Unit tests for EtsiTs103097DataEncryptedUnicast
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EtsiTs103097DataEncryptedUnicastSpec extends BaseStructSpec {

    def "Verify that constructor accepts valid signed data"(){
        when:
        def d = new EtsiTs103097DataEncryptedUnicast(2, genEncryptedData())
        then:
        serializeToHex(d) == "028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        when:
        def d2 = new EtsiTs103097DataEncryptedUnicast(Hex.decode("028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == encryptedData
    }

    def "Verify that constructor validates EtsiTs103097Data requirements"(){
        setup:
        EccP256CurvePoint v = new EccP256CurvePoint(new BigInteger(123))
        byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
        byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
        EciesP256EncryptedKey encKey = new EciesP256EncryptedKey(v,c,t)
        def extraRecipient = new RecipientInfo(RecipientInfo.RecipientInfoChoices.certRecipInfo,new PKRecipientInfo(new HashedId8(Hex.decode("0102030405060708")), new EncryptedDataEncryptionKey(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256, encKey)))
        when:
        new EtsiTs103097DataEncryptedUnicast(2, genEncryptedData(extraRecipient))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "EtsiTs103097Data with profile Encrypted-Unicast must exactly one recipient."
    }

    def "Verify that constructor throws IllegalArgumentException if data type is new encryptedData"(){
        when:
        new EtsiTs103097DataEncryptedUnicast(2, genSignedData())
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "EtsiTs103097Data with profile Encrypted must have content of type: encryptedData"
    }

}
