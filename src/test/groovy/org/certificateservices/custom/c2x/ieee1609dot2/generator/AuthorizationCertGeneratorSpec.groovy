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

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097Data
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned

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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
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
 * Test for AuthorizationCertGenerator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class AuthorizationCertGeneratorSpec extends BaseCertGeneratorSpec {


	@Unroll
	def "Verify that Ieee1609Dot2 Authorization Cert is generated correctly of explicit certificate for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair authCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair encKeys = cryptoManager.generateKeyPair(encAlg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		Certificate authCA = genAuthorizationCA(CertificateType.explicit,alg, authCAKeys, rootCAKeys, rootCA)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 33)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Enroll Cert"))
		byte[] cracaid = Hex.decode("010203")
		PsidSsp[] subjectPerms = new PsidSsp[1]
		subjectPerms[0] = new PsidSsp(new Psid(5), null)
		when:
		Certificate c1 = authcg.genAuthorizationCert(CertificateType.explicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), authCA, authCAKeys.publicKey, authCAKeys.privateKey, null, null, null)
		then:
		cryptoManager.verifyCertificate(c1, authCA)
		
		c1.getType() == CertificateType.explicit
		
		c1.getIssuer().getType() == (alg == PublicVerificationKeyChoices.ecdsaBrainpoolP384r1 ? IssuerIdentifierChoices.sha384AndDigest : IssuerIdentifierChoices.sha256AndDigest)
		c1.getIssuer().getValue() == new HashedId8(cryptoManager.digest(authCA.encoded, alg))
		c1.getToBeSigned().appPermissions.getSequenceValuesAsList().size() == 1
		
		c1.getToBeSigned().appPermissions.getSequenceValuesAsList()[0] == subjectPerms[0]
		
		c1.getToBeSigned().assuranceLevel.assuranceLevel == 7
		c1.getToBeSigned().assuranceLevel.confidenceLevel == 1
		
		c1.getToBeSigned().certIssuePermissions == null
		
		c1.getToBeSigned().certRequestPermissions == null
		
		c1.getToBeSigned().cracaId.hashedId == cracaid
		c1.getToBeSigned().crlSeries.value == 999
		
		c1.getToBeSigned().encryptionKey == null
		c1.getToBeSigned().id == id
		c1.getToBeSigned().region == region
		c1.getToBeSigned().validityPeriod == validityPeriod
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.verificationKey
		
		when:
		Certificate c2 = authcg.genAuthorizationCert(CertificateType.explicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), authCA, authCAKeys.publicKey, authCAKeys.privateKey, SymmAlgorithm.aes128Ccm, encAlg, encKeys.publicKey)
		then:
		
		cryptoManager.verifyCertificate(c2, authCA)
		
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
		KeyPair authCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
		Certificate authCA = genAuthorizationCA(CertificateType.explicit,alg, authCAKeys, rootCAKeys, rootCA)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSsp[] subjectPerms = new PsidSsp[1]
		subjectPerms[0] = new PsidSsp(new Psid(5), null)

		when:
		Certificate c1 = authcg.genAuthorizationCert(CertificateType.implicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), authCA, authCAKeys.publicKey, authCAKeys.privateKey, null, null, null)
		then:
		c1 instanceof ImplicitCertificateData
		c1.getType() == CertificateType.implicit
		
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.reconstructionValue
		
		when: "Verify that public and private key can be reconstructed using the certificate"
		PublicKey reconstructedPubKey = ecqvHelper.extractPublicKey(c1,authCAKeys.getPublic(), alg, authCA)
		PrivateKey reconstructedPrivateKey = ecqvHelper.certReceiption(c1,c1.getR(),alg, signKeys.getPrivate(), authCAKeys.getPublic(), authCA)
		
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
		KeyPair authCAKeys = cryptoManager.generateKeyPair(alg)
		KeyPair signKeys = cryptoManager.generateKeyPair(alg)
		
		Certificate rootCA = genRootCA(rootCAKeys)
		Certificate authCA = genAuthorizationCA(CertificateType.implicit,alg, authCAKeys, rootCAKeys, rootCA)
		
		PublicKey authCAPubKey = ecqvHelper.extractPublicKey(authCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey authCAPrivateKey = ecqvHelper.certReceiption(authCA, authCA.r, alg, authCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		
		ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 34)
		GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])
		CertificateId id = new CertificateId(new Hostname("Test Longterm CA"))
		byte[] cracaid = Hex.decode("010203")
		PsidSsp[] subjectPerms = new PsidSsp[1]
		subjectPerms[0] = new PsidSsp(new Psid(5), null)

		when:
		Certificate c1 = authcg.genAuthorizationCert(CertificateType.implicit, id, validityPeriod, region, subjectPerms, cracaid, 999, 7, 1, alg, signKeys.getPublic(), authCA, authCAPubKey, authCAPrivateKey, null, null, null)
		then:
		c1 instanceof ImplicitCertificateData
		c1.getType() == CertificateType.implicit
		
		c1.getToBeSigned().verifyKeyIndicator.type == VerificationKeyIndicatorChoices.reconstructionValue
		
		when: "Verify that public and private key can be reconstructed using the certificate"
		PublicKey reconstructedPubKey = ecqvHelper.extractPublicKey(c1,authCAPubKey, alg, authCA)
		PrivateKey reconstructedPrivateKey = ecqvHelper.certReceiption(c1,c1.getR(),alg, signKeys.getPrivate(), authCAPubKey, authCA)
		
		byte[] data = "TestData".getBytes()
		
		byte[] signature = signDataECDSA(data, reconstructedPrivateKey)
		then:
		verifySignedDataECDSA(data, signature, reconstructedPubKey)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
				
	}

}
