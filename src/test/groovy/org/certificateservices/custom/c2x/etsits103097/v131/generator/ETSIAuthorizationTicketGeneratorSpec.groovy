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
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec

/**
 * Unit tests for ETSIAuthorizationTicketGenerator
 *
 * @author Philip Vendil p.vendil@cgi.com
 */
class ETSIAuthorizationTicketGeneratorSpec extends BaseCertGeneratorSpec {

    def alg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
    def caKeys = staticNistP256KeyPair

    ETSIAuthorityCertGenerator eacg
    ETSIAuthorizationTicketGenerator eatg

    def rootCACert
    def authorizationCACert

    ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
    GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])

    def setup(){
        eacg = new ETSIAuthorityCertGenerator(cryptoManager)
        eatg = new ETSIAuthorizationTicketGenerator(cryptoManager)

        rootCACert = eacg.genRootCA("someName",validityPeriod, region,3,-1, Hex.decode("0138"),alg, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        authorizationCACert = eacg.genAuthorizationCA("SomeAuthorizationCAName",validityPeriod, region,new SubjectAssurance(2,0),alg, caKeys.public, rootCACert, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
    }

    def "Verify that Authorization Ticket conforms to profile."(){
        setup:
        PsidSsp testSSP1 = new PsidSsp(AvailableITSAID.CABasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"somebytes".getBytes()))
        PsidSsp testSSP2 = new PsidSsp(AvailableITSAID.DENBasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"otherbytes".getBytes()))

        PsidSsp[] appPermissions = [testSSP1,testSSP2] as PsidSsp[]
        when:
        def c = eatg.genAuthorizationTicket(validityPeriod,region,new SubjectAssurance(2,1),appPermissions,alg, caKeys.public, authorizationCACert, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        then:
        String issuerHash =  Hex.toHexString(new HashedId8(cryptoManager.digest(authorizationCACert.encoded, HashAlgorithm.sha256)).data)
        String certData = c.toString().replaceAll(issuerHash,"ISSUERHASH")
        certData.startsWith("""EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[sha256AndDigest=[ISSUERHASH]]
  toBeSigned=[
    id=[none]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [35 years]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
    assuranceLevel=[subjectAssurance=65 (assuranceLevel=2, confidenceLevel= 1 )]
    appPermissions=[[psid=[36(24)], ssp=[opaque=[736f6d656279746573]]],[psid=[37(25)], ssp=[opaque=[6f746865726279746573]]]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]""")

    }
}
