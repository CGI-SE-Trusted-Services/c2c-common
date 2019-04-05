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
import spock.lang.Specification

import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genEncryptedData
import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genEncryptedData
import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genSignedData
import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genUnsecuredContent
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData

/**
 * Unit tests for EtsiTs103097DataUnsecured
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EtsiTs103097DataUnsecuredSpec extends BaseStructSpec {

    def "Verify that constructor accepts valid unsecured data"(){
        when:
        def d = new EtsiTs103097DataUnsecured(2, genUnsecuredContent())
        then:
        serializeToHex(d) == "0280080102030405060708"
        when:
        def d2 = new EtsiTs103097DataUnsecured(Hex.decode("0280080102030405060708"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == unsecuredData
    }


    def "Verify that constructor throws IllegalArgumentException if data type is new encryptedData"(){
        when:
        new EtsiTs103097DataUnsecured(2, genSignedData())
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "EtsiTs103097Data with profile Unseured must be of type unsecured."
    }
}
