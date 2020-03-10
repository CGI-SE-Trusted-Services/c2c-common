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
package org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate

/**
 * Unit tests for SingleEtsiTs103097Certificate
 */
class SingleEtsiTs103097CertificateSpec extends BaseStructSpec {

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        setup:
        def c = genCert()
        when:
        SingleEtsiTs103097Certificate s = new SingleEtsiTs103097Certificate(c)
        then:
        serializeToHex(s) == "800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        SingleEtsiTs103097Certificate s2 = deserializeFromHex(new SingleEtsiTs103097Certificate(), "800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
        then:
        s2.getOnly() == c
    }

    def "Verify that IOException is thrown when encoding if not all fields are set"(){
        when:
        new SingleEtsiTs103097Certificate(null)
        then:
        thrown IOException
    }

    def "Verify toString()"(){
        expect:
        new SingleEtsiTs103097Certificate(genCert()).toString() == """SingleEtsiTs103097Certificate [only=EtsiTs103097Certificate [
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
]]"""
    }


    static EtsiTs103097Certificate genCert(String hostname="SomeCertId"){
        CertificateId id = new CertificateId(new Hostname(hostname))
        ToBeSignedCertificate toBeSigned = EtsiTs103097CertificateSpec.genToBeSignedCertificate(id)
        IssuerIdentifier issuerId = new IssuerIdentifier(HashAlgorithm.sha256)
        Signature signature = new Signature(Signature.SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(new EccP256CurvePoint(new BigInteger(123)), COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)))

        return new EtsiTs103097Certificate(issuerId,toBeSigned,signature)
    }
}
