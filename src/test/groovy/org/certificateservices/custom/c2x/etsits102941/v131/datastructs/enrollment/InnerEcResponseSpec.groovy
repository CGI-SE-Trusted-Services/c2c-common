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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.SingleEtsiTs103097CertificateSpec

/**
 * Unit tests for InnerEcResponse
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class InnerEcResponseSpec extends BaseStructSpec {

    byte[] requestHash = Hex.decode("00112233445566778899001122334455")
    EtsiTs103097Certificate certificate = SingleEtsiTs103097CertificateSpec.genCert()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        InnerEcResponse r = new InnerEcResponse(requestHash, EnrollmentResponseCode.ok, certificate)
        then:
        serializeToHex(r) == "400011223344556677889900112233445500800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        InnerEcResponse r2 = deserializeFromHex(new InnerEcResponse(), "400011223344556677889900112233445500800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
        then:
        r2.getRequestHash() == requestHash
        r2.getResponseCode() == EnrollmentResponseCode.ok
        r2.getCertificate() == certificate

        when:
        InnerEcResponse r3 = new InnerEcResponse(requestHash, EnrollmentResponseCode.badcontenttype, null)
        then:
        serializeToHex(r3) == "000011223344556677889900112233445502"
        when:
        InnerEcResponse r4 = deserializeFromHex(new InnerEcResponse(), "000011223344556677889900112233445502")
        then:
        r4.getRequestHash() == requestHash
        r4.getResponseCode() == EnrollmentResponseCode.badcontenttype
        r4.getCertificate() == null
    }

    def "Verify that constructor throws IllegalArgumentException if response code is not ok but certificate is set"(){
        when:
        new InnerEcResponse(requestHash, EnrollmentResponseCode.badcontenttype, certificate)
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Illegal argument: certificate must be null if response code is not ok."
    }

    def "Verify that constructor throws IllegalArgumentException if response code is  ok but certificate is not set"(){
        when:
        new InnerEcResponse(requestHash, EnrollmentResponseCode.ok, null)
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Illegal argument: certificate cannot be null if response code is ok."
    }

    def fullToString = """InnerEcResponse [
  requestHash=00112233445566778899001122334455
  responseCode=ok
  certificate=[
    version=3
    type=explicit
    issuer=[self=sha256]
    toBeSigned=[
      id=[name=[SomeCertId]]
      cracaId=[313233]
      crlSeries=[432]
      validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
      region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
      assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
      appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
      certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
      certRequestPermissions=NONE
      canRequestRollover=false
      encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
      verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
    ]
    signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
  ]
]"""

    def noCertToString = """InnerEcResponse [
  requestHash=00112233445566778899001122334455
  responseCode=badcontenttype
  certificate=NONE
]"""

    def "Verify toString()"(){
        expect:
        new InnerEcResponse(requestHash, EnrollmentResponseCode.ok, certificate).toString() == fullToString
        new InnerEcResponse(requestHash, EnrollmentResponseCode.badcontenttype, null).toString() == noCertToString
    }
}
