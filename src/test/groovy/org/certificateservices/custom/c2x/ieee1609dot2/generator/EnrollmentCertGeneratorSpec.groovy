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
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EnrollmentCertGenerator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class EnrollmentCertGeneratorSpec extends BaseCertGeneratorSpec {

	
	@Unroll
	def "Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of explicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys = cryptoManager.generateKeyPair(encAlg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit,alg, enrollCAKeys, rootCAKeys, rootCA)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 33)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Enroll Cert"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))
		when:
		Certificate c1 = ecg.genEnrollCert(CertificateType.explicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), enrollCA, enrollCAKeys.publicKey, enrollCAKeys.privateKey, null, null, null)
		then:
		cryptoManager.verifyCertificate(c1, enrollCA)
		
		c1.getType() == CertificateType.explicit
		
		c1.getIssuer().getType() == (alg == PublicVerificationKeyChoices.ecdsaBrainpoolP384r1 ? IssuerIdentifierChoices.sha384AndDigest : IssuerIdentifierChoices.sha256AndDigest)
		c1.getIssuer().getValue() == new HashedId8(cryptoManager.digest(enrollCA.encoded, alg))
		c1.getToBeSigned().appPermissions == null
		
		c1.getToBeSigned().assuranceLevel.assuranceLevel == 7
		c1.getToBeSigned().assuranceLevel.confidenceLevel == 1
		
		c1.getToBeSigned().certIssuePermissions == null
		
		c1.getToBeSigned().certRequestPermissions.getSequenceValuesAsList().size() == 1
		PsidGroupPermissions pgp = c1.getToBeSigned().certRequestPermissions.getSequenceValuesAsList()[0]
		pgp.getSubjectPermissions().type == SubjectPermissionsChoices.explicit
		((SequenceOfPsidSspRange) pgp.getSubjectPermissions().value).sequenceValuesAsList.size() == 1
		((SequenceOfPsidSspRange) pgp.getSubjectPermissions().value).sequenceValuesAsList[0] == subjectPerms[0]
		pgp.getMinChainDepth() == 0
		pgp.getChainDepthRange() == 0
		pgp.getEEType().app
		!pgp.getEEType().enroll
		
	
		c1.getToBeSigned().cracaId.hashedId == cracaid
		c1.getToBeSigned().crlSeries.value == 999
		
		c1.getToBeSigned().encryptionKey == null
		c1.getToBeSigned().id == id
		c1.getToBeSigned().region == region
		c1.getToBeSigned().validityPeriod == validityPeriod
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.verificationKey
		
		when:
		Certificate c2 = ecg.genEnrollCert(CertificateType.explicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), enrollCA, enrollCAKeys.publicKey, enrollCAKeys.privateKey, SymmAlgorithm.aes128Ccm, encAlg, encKeys.publicKey)
		then:
		
		cryptoManager.verifyCertificate(c2, enrollCA)
		
		c2.getToBeSigned().getEncryptionKey().getSupportedSymmAlg() == SymmAlgorithm.aes128Ccm
		c2.getToBeSigned().getEncryptionKey().getPublicKey().type == encAlg
		cryptoManager.decodeEccPoint(encAlg, (EccP256CurvePoint) c2.getToBeSigned().getEncryptionKey().getPublicKey().getValue()) == encKeys.publicKey

		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1, PublicVerificationKeyChoices.ecdsaBrainpoolP384r1]
		encAlg << [BasePublicEncryptionKeyChoices.ecdsaNistP256, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1, BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1]
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Enrollment Cert is generated correctly of implicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit,alg, enrollCAKeys, rootCAKeys, rootCA)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))

		when:
		Certificate c1 = ecg.genEnrollCert(CertificateType.implicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), enrollCA, enrollCAKeys.publicKey, enrollCAKeys.privateKey, null, null, null)
		then:
		c1 instanceof ImplicitCertificateData
		c1.getType() == CertificateType.implicit
		
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.reconstructionValue
		
		when: "Verify that public and private key can be reconstructed using the certificate"
		PublicKey reconstructedPubKey = ecqvHelper.extractPublicKey(c1,enrollCAKeys.getPublic(), alg, enrollCA)
		PrivateKey reconstructedPrivateKey = ecqvHelper.certReceiption(c1,c1.getR(),alg, signKeys.getPrivate(), enrollCAKeys.getPublic(), enrollCA)
		
		byte[] data = "TestData".getBytes()
		
		byte[] signature = signDataECDSA(data, reconstructedPrivateKey)
		then:
		verifySignedDataECDSA(data, signature, reconstructedPubKey)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
				
	}
	
	@Unroll
	def "Verify that Ieee1609Dot2 Enrollment Cert is generated correctly for implicit CA certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit,alg, enrollCAKeys, rootCAKeys, rootCA)
		
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSspRange[] subjectPerms = new PsidSspRange[1]
		subjectPerms[0] = new PsidSspRange(new Psid(5), new SspRange(SspRangeChoices.all, null))

		when:
		Certificate c1 = ecg.genEnrollCert(CertificateType.implicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), enrollCA, enrollCAPubKey, enrollPrivateKey, null, null, null)
		then:
		c1 instanceof ImplicitCertificateData
		c1.getType() == CertificateType.implicit
		
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.reconstructionValue
		
		when: "Verify that public and private key can be reconstructed using the certificate"
		PublicKey reconstructedPubKey = ecqvHelper.extractPublicKey(c1,enrollCAPubKey, alg, enrollCA)
		PrivateKey reconstructedPrivateKey = ecqvHelper.certReceiption(c1,c1.getR(),alg, signKeys.getPrivate(), enrollCAPubKey, enrollCA)
		
		byte[] data = "TestData".getBytes()
		
		byte[] signature = signDataECDSA(data, reconstructedPrivateKey)
		then:
		verifySignedDataECDSA(data, signature, reconstructedPubKey)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
				
	}

}
