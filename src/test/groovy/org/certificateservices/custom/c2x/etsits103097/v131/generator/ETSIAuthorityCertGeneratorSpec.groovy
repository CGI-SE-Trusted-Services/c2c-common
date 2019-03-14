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
import org.certificateservices.custom.c2x.etsits103097.v131.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec

/**
 * Unit tests for ETSIAuthorityCertGenerator
 *
 * @author Philip Vendil p.vendil@cgi.com
 */
class ETSIAuthorityCertGeneratorSpec extends BaseCertGeneratorSpec {

    def alg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
    def caKeys = staticNistP256KeyPair

    ETSIAuthorityCertGenerator eacg

    def setup(){
        eacg = new ETSIAuthorityCertGenerator(cryptoManager)
    }

    def "Verify that Root CA Generator generates certificate that conforms to profile"(){
        setup:
        ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
        when:
        EtsiTs103097Certificate c = eacg.genRootCA("someName",validityPeriod, region,3,-1, Hex.decode("0138"),alg, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        then:
        //println c
        c.toString().startsWith("""EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[someName]]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [35 years]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
    assuranceLevel=NONE
    appPermissions=[[psid=[622(26e)], ssp=[opaque=[01]]],[psid=[624(270)], ssp=[opaque=[0138]]]]
    certIssuePermissions=[[subjectPermissions=[all], minChainDepth=3, chainDepthRange=-1, eeType=[app=true, enroll=true]]]
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]""")

    }

    def "Verify that Trust List Manager Generator generates certificate that conforms to profile"(){
        setup:
        ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
        when:
        EtsiTs103097Certificate c = eacg.genTrustListManagerCert("someName",validityPeriod, region,Hex.decode("01C8"),alg, caKeys.public, caKeys.private)
        then:
        c.toString().startsWith("""EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[someName]]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [35 years]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
    assuranceLevel=NONE
    appPermissions=[[psid=[624(270)], ssp=[opaque=[01c8]]]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]""")

    }

    def "Verify that Enrollment CA generates certificate that conforms to profile"(){
        setup:
        ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
        EtsiTs103097Certificate rootCA = eacg.genRootCA("someName",validityPeriod, region,3,-1, Hex.decode("0138"),alg, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        when:
        EtsiTs103097Certificate c = eacg.genEnrollmentCA("someEnrollmentCAName",validityPeriod, region,new SubjectAssurance(2,0),alg, caKeys.public, rootCA, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        then:
        String issuerHash =  Hex.toHexString(new HashedId8(cryptoManager.digest(rootCA.encoded,HashAlgorithm.sha256)).data)
        String certData = c.toString().replaceAll(issuerHash,"ISSUERHASH")
        certData.startsWith("""EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[sha256AndDigest=[ISSUERHASH]]
  toBeSigned=[
    id=[name=[someEnrollmentCAName]]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [35 years]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
    assuranceLevel=[subjectAssurance=64 (assuranceLevel=2, confidenceLevel= 0 )]
    appPermissions=[[psid=[623(26f)], ssp=[opaque=[010e]]]]
    certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=false, enroll=true]]]
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]""")

    }

    def "Verify that Authority CA generates certificate that conforms to profile"(){
        setup:
        ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
        GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
        EtsiTs103097Certificate rootCA = eacg.genRootCA("someName",validityPeriod, region,3,-1, Hex.decode("0138"),alg, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        when:
        EtsiTs103097Certificate c = eacg.genAuthorizationCA("someAuthorityCAName",validityPeriod, region,new SubjectAssurance(2,0),alg, caKeys.public, rootCA, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        then:
        String issuerHash =  Hex.toHexString(new HashedId8(cryptoManager.digest(rootCA.encoded,HashAlgorithm.sha256)).data)
        String certData = c.toString().replaceAll(issuerHash,"ISSUERHASH")
        certData.startsWith("""EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[sha256AndDigest=[ISSUERHASH]]
  toBeSigned=[
    id=[name=[someAuthorityCAName]]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [35 years]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
    assuranceLevel=[subjectAssurance=64 (assuranceLevel=2, confidenceLevel= 0 )]
    appPermissions=[[psid=[623(26f)], ssp=[opaque=[0132]]]]
    certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=false]]]
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]""")

    }
}
