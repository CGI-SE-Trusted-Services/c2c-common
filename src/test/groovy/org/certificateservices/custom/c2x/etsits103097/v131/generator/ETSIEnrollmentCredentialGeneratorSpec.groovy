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
package org.certificateservices.custom.c2x.etsits103097.v131.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec

/**
 * Unit tests for ETSIEnrollmentCertGenerator
 *
 * @author Philip Vendil p.vendil@cgi.com
 */
class ETSIEnrollmentCredentialGeneratorSpec extends BaseCertGeneratorSpec {

    def alg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
    def caKeys = staticNistP256KeyPair

    ETSIAuthorityCertGenerator eacg
    ETSIEnrollmentCredentialGenerator eecg

    def rootCACert
    def enrollmentCACert

    ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
    GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])

    def setup(){
        eacg = new ETSIAuthorityCertGenerator(cryptoManager)
        eecg = new ETSIEnrollmentCredentialGenerator(cryptoManager)

        rootCACert = eacg.genRootCA("someName",validityPeriod, region,3,-1, Hex.decode("0138"),alg, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        enrollmentCACert = eacg.genEnrollmentCA("someEnrollmentCAName",validityPeriod, region,new SubjectAssurance(2,0),alg, caKeys.public, rootCACert, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)

    }

    def "Verify that Enrollment Certificate conforms to profile"(){
        when:
        def c = eecg.genEnrollCredential("EnrollmentCert",validityPeriod,region,Hex.decode("01C0"),2,1,alg, caKeys.public, enrollmentCACert, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        then:
        String issuerHash =  Hex.toHexString(new HashedId8(cryptoManager.digest(enrollmentCACert.encoded, HashAlgorithm.sha256)).data)
        String certData = c.toString().replaceAll(issuerHash,"ISSUERHASH")

        certData.startsWith("""EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[sha256AndDigest=[ISSUERHASH]]
  toBeSigned=[
    id=[name=[EnrollmentCert]]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [35 years]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
    assuranceLevel=[subjectAssurance=65 (assuranceLevel=2, confidenceLevel= 1 )]
    appPermissions=[[psid=[623(26f)], ssp=[opaque=[01c0]]]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]""")

    }


}
