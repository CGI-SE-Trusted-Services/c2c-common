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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion.GeographicRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

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
		pgp.getAppPermissions().type == SubjectPermissionsChoices.all
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
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
		encAlg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Long term CA is generated correctly of explicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys = cryptoManager.generateKeyPair(encAlg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
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
		
		c1.getIssuer().getType() == IssuerIdentifierChoices.sha256AndDigest
		c1.getIssuer().getValue() == new HashedId8(cryptoManager.digest(rootCA.encoded, HashAlgorithm.sha256))
		c1.getToBeSigned().appPermissions == null
		
		c1.getToBeSigned().assuranceLevel.assuranceLevel == 7
		c1.getToBeSigned().assuranceLevel.confidenceLevel == 0
		
		c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList().size() == 1
		PsidGroupPermissions pgp = c1.getToBeSigned().certIssuePermissions.getSequenceValuesAsList()[0]
		pgp.getAppPermissions().type == SubjectPermissionsChoices.explicit
		((SequenceOfPsidSspRange) pgp.getAppPermissions().value).sequenceValuesAsList.size() == 1
		((SequenceOfPsidSspRange) pgp.getAppPermissions().value).sequenceValuesAsList[0] == subjectPerms[0]
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
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
		encAlg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Long term CA is generated correctly of implicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
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
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
				
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Short term CA is generated correctly of explicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
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
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
		
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
