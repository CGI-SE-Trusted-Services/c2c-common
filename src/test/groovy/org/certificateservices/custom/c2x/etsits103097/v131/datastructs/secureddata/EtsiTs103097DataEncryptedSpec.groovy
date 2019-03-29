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
package org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PreSharedKeyRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo

import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.*
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData

/**
 * Unit tests for EtsiTs103097DataEncrypted
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EtsiTs103097DataEncryptedSpec extends BaseStructSpec {

    def "Verify that constructor accepts valid signed data"(){
        when:
        def d = new EtsiTs103097DataEncrypted(2, genEncryptedData())
        then:
        serializeToHex(d) == "028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        when:
        def d2 = new EtsiTs103097DataEncrypted(Hex.decode("028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == encryptedData
    }

    def "Verify that constructor throws IllegalArgumentException if data type is new encryptedData"(){
        when:
        new EtsiTs103097DataEncrypted(2, genSignedData())
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "EtsiTs103097Data with profile Encrypted must have content of type: encryptedData"
    }



}
