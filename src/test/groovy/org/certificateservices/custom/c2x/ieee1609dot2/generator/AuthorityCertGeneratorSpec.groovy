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
package org.certificateservices.custom.c2x.ieee1609dot2.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp.CracaType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp.CrlSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp.PermissibleCrls
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices
import spock.lang.Unroll

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Test for AuthorityCertGenerator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class AuthorityCertGeneratorSpec extends BaseCertGeneratorSpec {
	
	@Unroll
	def "Verify that Ieee1609Dot2 Root CA is generated correctly for explicit certificate (only type supported) for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys = cryptoManager.generateKeyPair(encAlg)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test RootCA"))
		when:
		Certificate c1 = acg.genRootCA(id, validityPeriod, region, 7, 0, 3, 4, alg, rootCAKeys.public, rootCAKeys.private, null, null, null)
		then:
		c1 != null
		
		cryptoManager.verifyCertificate(c1, c1)
		
		c1.getType() == CertificateType.explicit
		
		c1.getIssuer().getType() == IssuerIdentifierChoices.self
		c1.getToBeSigned().appPermissions == null
		
		c1.getToBeSigned().assuranceLevel.assuranceLevel == 7
		c1.getToBeSigned().assuranceLevel.confidenceLevel == 0
		
		c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList().size() == 1
		PsidGroupPermissions pgp = c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList()[0]
		pgp.getSubjectPermissions().type == SubjectPermissionsChoices.all
		pgp.getMinChainDepth() == 3
		pgp.getChainDepthRange() == 4
		pgp.getEEType().app
		pgp.getEEType().enroll
		
		c1.getToBeSigned().certRequestPermissions == null
		
		c1.getToBeSigned().cracaId == new HashedId3(Hex.decode("000000"))
		c1.getToBeSigned().crlSeries.value == 0
		
		c1.getToBeSigned().encryptionKey == null
		c1.getToBeSigned().id == id
		c1.getToBeSigned().region == region
		c1.getToBeSigned().validityPeriod == validityPeriod
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.verificationKey
		
		when:
		Certificate c2 = acg.genRootCA(id, validityPeriod, region, 7, 0, 3, 4, alg, rootCAKeys.public, rootCAKeys.private, SymmAlgorithm.aes128Ccm, 
			encAlg, encKeys.public)
		then:
		cryptoManager.verifyCertificate(c2, c2)
		
		c2.getToBeSigned().getEncryptionKey().getSupportedSymmAlg() == SymmAlgorithm.aes128Ccm
		c2.getToBeSigned().getEncryptionKey().getPublicKey().type == encAlg
		cryptoManager.decodeEccPoint(encAlg, (EccP256CurvePoint) c2.getToBeSigned().getEncryptionKey().getPublicKey().getValue()) == encKeys.public
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1,PublicVerificationKeyChoices.ecdsaBrainpoolP384r1]
		encAlg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}

	def "Test to generate a root certificate according to the profile i IEEE 1609.2 D 5.4"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		CertificateId id = new CertificateId(new Hostname("v2xrootca.ghsiss.com"))
		KeyPair rootCAKeys = staticNistP256KeyPair
		long validityPeriodStart = 385689600000L
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(validityPeriodStart), DurationChoices.years, 70)
		int ScmsSpclComponentCrlSeries = 256
		Psid SecurityMgmtPsid = new Psid(35)
		Psid MisbehaviorReportingPsid = new Psid(38)
		Psid CrlPsid = new Psid(256)
		CrlSsp crlSsp = new CrlSsp(CracaType.isCraca,new PermissibleCrls(new CrlSeries(ScmsSpclComponentCrlSeries)))
		ServiceSpecificPermissions crlSspPerm = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, COEREncodeHelper.encode(crlSsp))
		def appPermissions = [new PsidSsp(SecurityMgmtPsid,null),new PsidSsp(CrlPsid,crlSspPerm)] as PsidSsp[]
		def certIssuePermissions = [new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all,null),3,-1, new EndEntityType(true,true)),
									new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.explicit,new SequenceOfPsidSspRange([new PsidSspRange(SecurityMgmtPsid,null)])),1,-1, new EndEntityType(true,true)),
									new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.explicit,new SequenceOfPsidSspRange([new PsidSspRange(MisbehaviorReportingPsid,null)])),1,-1, new EndEntityType(true,true)),
									new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.explicit,new SequenceOfPsidSspRange([new PsidSspRange(CrlPsid,new SspRange(SspRangeChoices.all))])),1,-1, new EndEntityType(true,true))
		] as PsidGroupPermissions[]
		when:
		Certificate c1 = acg.genRootCA(id, validityPeriod, null, null, appPermissions,certIssuePermissions, alg, rootCAKeys.public, rootCAKeys.private, null, null, null)
		then:
		c1.toString().startsWith( """Certificate [
  version=3
  type=explicit
  issuer=[self=sha256]
  toBeSigned=[
    id=[name=[v2xrootca.ghsiss.com]]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Tue Mar 23 01:00:00 CET 1982 (-687225612)], duration=Duration [70 years]]
    region=NONE
    assuranceLevel=NONE
    appPermissions=[[psid=[35(23)], ssp=NULL],[psid=[256(100)], ssp=[opaque=[00010001010100]]]]
    certIssuePermissions=[[subjectPermissions=[all], minChainDepth=3, chainDepthRange=-1, eeType=[app=true, enroll=true]],[subjectPermissions=[explicit=[[psid=[35(23)], sspRange=NULL]]], minChainDepth=1, chainDepthRange=-1, eeType=[app=true, enroll=true]],[subjectPermissions=[explicit=[[psid=[38(26)], sspRange=NULL]]], minChainDepth=1, chainDepthRange=-1, eeType=[app=true, enroll=true]],[subjectPermissions=[explicit=[[psid=[256(100)], sspRange=[all]]]], minChainDepth=1, chainDepthRange=-1, eeType=[app=true, enroll=true]]]
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[""")

	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Long term CA is generated correctly of explicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys = cryptoManager.generateKeyPair(encAlg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys,alg)
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))
		when:
		Certificate c1 = acg.genLongTermEnrollmentCA(CertificateType.explicit, id, validityPeriod, region, subjectPerms,cracaid, 999, 7,0,3,3,alg,
			signKeys.getPublic(),
			rootCA,
			rootCAKeys.getPublic(),
			rootCAKeys.getPrivate(),
			null,
			null,
			null)
		then:
		cryptoManager.verifyCertificate(c1, rootCA)
		
		c1.getType() == CertificateType.explicit
		
		c1.getIssuer().getType() == (alg == PublicVerificationKeyChoices.ecdsaBrainpoolP384r1 ? IssuerIdentifierChoices.sha384AndDigest : IssuerIdentifierChoices.sha256AndDigest)
		c1.getIssuer().getValue() == new HashedId8(cryptoManager.digest(rootCA.encoded, alg))
		c1.getToBeSigned().appPermissions == null
		
		c1.getToBeSigned().assuranceLevel.assuranceLevel == 7
		c1.getToBeSigned().assuranceLevel.confidenceLevel == 0
		
		c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList().size() == 1
		PsidGroupPermissions pgp = c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList()[0]
		pgp.getSubjectPermissions().type == SubjectPermissionsChoices.explicit
		((SequenceOfPsidSspRange) pgp.getSubjectPermissions().value).sequenceValuesAsList.size() == 1
		((SequenceOfPsidSspRange) pgp.getSubjectPermissions().value).sequenceValuesAsList[0] == subjectPerms[0]
		pgp.getMinChainDepth() == 3
		pgp.getChainDepthRange() == 3
		!pgp.getEEType().app
		pgp.getEEType().enroll
		
		c1.getToBeSigned().certRequestPermissions == null
		
		c1.getToBeSigned().cracaId.hashedId == cracaid
		c1.getToBeSigned().crlSeries.value == 999
		
		c1.getToBeSigned().encryptionKey == null
		c1.getToBeSigned().id == id
		c1.getToBeSigned().region == region
		c1.getToBeSigned().validityPeriod == validityPeriod
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.verificationKey
		
		when:
		Certificate c2 = acg.genLongTermEnrollmentCA(CertificateType.explicit, id, validityPeriod, region, subjectPerms,cracaid, 999, 7,0,3,3,alg,
			signKeys.getPublic(),
			rootCA,
			rootCAKeys.getPublic(),
			rootCAKeys.getPrivate(),
			SymmAlgorithm.aes128Ccm, 
			encAlg, encKeys.public)
		then:
		
		cryptoManager.verifyCertificate(c2, rootCA)
		
		c2.getToBeSigned().getEncryptionKey().getSupportedSymmAlg() == SymmAlgorithm.aes128Ccm
		c2.getToBeSigned().getEncryptionKey().getPublicKey().type == encAlg
		cryptoManager.decodeEccPoint(encAlg, (EccP256CurvePoint) c2.getToBeSigned().getEncryptionKey().getPublicKey().getValue()) == encKeys.public

		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1, PublicVerificationKeyChoices.ecdsaBrainpoolP384r1]
		encAlg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Long term CA is generated correctly of implicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))
		when:
		Certificate c1 = acg.genLongTermEnrollmentCA(CertificateType.implicit, id, validityPeriod, region, subjectPerms,cracaid, 999, 7,0,3,3,alg,
			signKeys.getPublic(),
			rootCA,
			rootCAKeys.getPublic(),
			rootCAKeys.getPrivate(),
			null,
			null,
			null)
		then:
		c1 instanceof ImplicitCertificateData
		c1.getType() == CertificateType.implicit
		
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.reconstructionValue
		
		when: "Verify that public and private key can be reconstructed using the certificate"
		PublicKey reconstructedPubKey = ecqvHelper.extractPublicKey(c1,rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey reconstructedPrivateKey = ecqvHelper.certReceiption(c1,c1.getR(),alg, signKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		
		byte[] data = "TestData".getBytes()
		
		byte[] signature = signDataECDSA(data, reconstructedPrivateKey)
		then:
		verifySignedDataECDSA(data, signature, reconstructedPubKey)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
				
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Short term CA is generated correctly of explicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))
		when:
		Certificate c1 = acg.genAuthorizationCA(CertificateType.explicit, id, validityPeriod, region, subjectPerms,cracaid, 999, 7,0,3,3,alg,
			signKeys.getPublic(),
			rootCA,
			rootCAKeys.getPublic(),
			rootCAKeys.getPrivate(),
			null,
			null,
			null)
		then:
		cryptoManager.verifyCertificate(c1, rootCA)
		
		PsidGroupPermissions pgp = c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList()[0]
		pgp.getEEType().app
		!pgp.getEEType().enroll
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1, PublicVerificationKeyChoices.ecdsaBrainpoolP384r1]
		
	}
	
	@Unroll
	def "Verify that getPublicVerificationAlgorithm returns correct PublicVerificationKeyChoice #expectedAlg for alg: #alg"(){
		expect:
		acg.getPublicVerificationAlgorithm(alg) == expectedAlg
		where:
		alg                                                    | expectedAlg
		EncryptedDataEncryptionKeyChoices.eciesNistP256        | PublicVerificationKeyChoices.ecdsaNistP256
		EncryptedDataEncryptionKeyChoices.eciesBrainpoolP256r1 | PublicVerificationKeyChoices.ecdsaBrainpoolP256r1
		PublicVerificationKeyChoices.ecdsaNistP256             | PublicVerificationKeyChoices.ecdsaNistP256
		PublicVerificationKeyChoices.ecdsaBrainpoolP256r1      | PublicVerificationKeyChoices.ecdsaBrainpoolP256r1
	}


}
