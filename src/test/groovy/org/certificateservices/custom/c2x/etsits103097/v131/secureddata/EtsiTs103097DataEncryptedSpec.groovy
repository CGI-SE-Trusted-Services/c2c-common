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
package org.certificateservices.custom.c2x.etsits103097.v131.secureddata

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.AesCcmCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PreSharedKeyRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SequenceOfRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*

import static org.certificateservices.custom.c2x.etsits103097.v131.cert.SingleEtsiTs103097CertificateSpec.genCert
import static org.certificateservices.custom.c2x.etsits103097.v131.secureddata.EtsiTs103097DataSpec.*
import static org.certificateservices.custom.c2x.etsits103097.v131.secureddata.EtsiTs103097DataSpec.genSignedData
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.encryptedData
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData

/**
 * Unit tests for EtsiTs103097DataEncrypted
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

    def "Verify that constructor validates EtsiTs103097Data requirements"(){
        when:
        new EtsiTs103097DataEncrypted(2, genEncryptedData(new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708")))))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, encrypted data recipient cannot be of type: pskRecipInfo"
    }

    def "Verify that constructor throws IllegalArgumentException if data type is new encryptedData"(){
        when:
        new EtsiTs103097DataEncrypted(2, genSignedData())
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "EtsiTs103097Data with profile Encrypted must have content of type: encryptedData"
    }



}
