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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.camanagement


import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.InnerAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.SharedAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.CertificateSubjectAttributes
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.PublicKeys

/**
 * Unit tests for CaCertificateRequest
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CaCertificateRequestSpec extends BaseStructSpec {

    PublicKeys publicKeys = InnerAtRequestSpec.genPublicKeys()
    CertificateSubjectAttributes requestedSubjectAttributes = SharedAtRequestSpec.genCertificateSubjectAttributes()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        CaCertificateRequest r = new CaCertificateRequest(publicKeys, requestedSubjectAttributes)
        then:
        serializeToHex(r) == "00808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        CaCertificateRequest r2 = deserializeFromHex(new CaCertificateRequest(), "00808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5")
        then:
        r2.getPublicKeys() == publicKeys
        r2.getRequestedSubjectAttributes() == requestedSubjectAttributes

    }

    def "Verify toString()"(){
        expect:
        new CaCertificateRequest(publicKeys, requestedSubjectAttributes).toString() == """CaCertificateRequest [
  publicKeys=[verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]]]
  requestedSubjectAttributes=[
    id=[name=[SomeCertId]]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
    assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=NONE
  ]
]"""
    }
}
