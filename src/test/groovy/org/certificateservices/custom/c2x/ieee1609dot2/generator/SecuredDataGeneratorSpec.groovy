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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier.IssuerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier.SignerIdentifierChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator.SignerIdentifierType;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SecuredDataGenerator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SecuredDataGeneratorSpec extends BaseCertGeneratorSpec {

	@Unroll
	def "Verify that signed Ieee1609Dot2Data with signed data is generated correctly for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, alg, enrollCA)
		PrivateKey enrollCertPrivateKey = ecqvHelper.certReceiption(enrollCert, enrollCert.r, alg, enrollCertKeys.privateKey, enrollCAPubKey, enrollCA)
		SecuredDataGenerator sdg = sdg_ecdsaNistP256
		if(alg == PublicVerificationKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		HeaderInfo hi = new HeaderInfo(new Psid(8), null,null,null,null,null,null)
		when:
		Ieee1609Dot2Data sd = sdg.genSignedData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.HASH_ONLY,[enrollCert, enrollCA, rootCA] as Certificate[], enrollCertPrivateKey)
		then:
		sd.getContent().getType() == Ieee1609Dot2ContentChoices.signedData
		SignedData signedData = sd.getContent().getValue()
		signedData.getSignature() != null
		signedData.getSigner().getType() == SignerIdentifierChoices.digest
		signedData.getTbsData().getHeaderInfo() == hi
		Ieee1609Dot2Data unsecuredData = ((SignedDataPayload) signedData.getTbsData().getPayload()).getData()
		unsecuredData.getContent().getType() == Ieee1609Dot2ContentChoices.unsecuredData
		unsecuredData.getContent().getValue().getData() == "TestData".getBytes("UTF-8")

		when:
		def certStore = sdg.buildCertStore([enrollCA,enrollCert])
		def trustStore = sdg.buildCertStore([rootCA])
		then:
		sdg.verifySignedData(sd,  certStore, trustStore)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}

	@Unroll
	def "Verify that signed Ieee1609Dot2Data with hashed refernce is generated correctly for alg: #alg"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys, alg)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, alg, enrollCA)
		PrivateKey enrollCertPrivateKey = ecqvHelper.certReceiption(enrollCert, enrollCert.r, alg, enrollCertKeys.privateKey, enrollCAPubKey, enrollCA)
		SecuredDataGenerator sdg = sdg_ecdsaNistP256
		if(alg == PublicVerificationKeyChoices.ecdsaBrainpoolP256r1){
			sdg = sdg_ecdsaBrainpoolP256r1
		}
		HeaderInfo hi = new HeaderInfo(new Psid(8), null,null,null,null,null,null)

		when:
		Ieee1609Dot2Data sd = sdg.genReferencedSignedData(hi, "TestData".getBytes("UTF-8"), SignerIdentifierType.CERT_CHAIN,[enrollCert, enrollCA, rootCA] as Certificate[], enrollCertPrivateKey)

		then:
		sd.getContent().getType() == Ieee1609Dot2ContentChoices.signedData
		SignedData signedData = sd.getContent().getValue()
		signedData.getSignature() != null
		signedData.getSigner().getType() == SignerIdentifierChoices.certificate
		signedData.getTbsData().getHeaderInfo() == hi
		HashedData hashedData = ((SignedDataPayload) signedData.getTbsData().getPayload()).getExtDataHash()
		hashedData.getType() == HashedDataChoices.sha256HashedData
		hashedData.getValue().getData() == cryptoManager.digest("TestData".getBytes("UTF-8"), HashAlgorithm.sha256)

		when:
		def trustStore = sdg.buildCertStore([rootCA])
		then:
		sdg.verifyReferencedSignedData(sd, "TestData".getBytes("UTF-8"), [:], trustStore)
		!sdg.verifyReferencedSignedData(sd, "InvalidData".getBytes("UTF-8"), [:], trustStore)
		
		where:
		alg << [PublicVerificationKeyChoices.ecdsaNistP256, PublicVerificationKeyChoices.ecdsaBrainpoolP256r1]
	}

	def "Verify that return first certificates public key of complete chain consists of explicit certificates"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		when:
		PublicKey pk = sdg.getSignerPublicKey([enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		pk == enrollCertKeys.publicKey
	}

	def "Verify that return first certificates public key of enroll cert only consists of implicit certificates"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAKeys.publicKey, alg, enrollCA)

		when:
		PublicKey pk = sdg.getSignerPublicKey([enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		pk == enrollCertExtractedKey
	}

	def "Verify that return first certificates public key of enroll cert and enroll ca consists of implicit certificates"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		PublicKey enrollCAPubKey = ecqvHelper.extractPublicKey(enrollCA, rootCAKeys.getPublic(), alg, rootCA)
		PrivateKey enrollCAPrivateKey = ecqvHelper.certReceiption(enrollCA, enrollCA.r, alg, enrollCAKeys.getPrivate(), rootCAKeys.getPublic(), rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.implicit, alg, enrollCertKeys, enrollCAPubKey, enrollCAPrivateKey, enrollCA)

		PublicKey enrollCertExtractedKey = ecqvHelper.extractPublicKey(enrollCert, enrollCAPubKey, alg, enrollCA)

		when:
		PublicKey pk = sdg.getSignerPublicKey([enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		pk == enrollCertExtractedKey
	}

	def "Verify that getSignerIdentifier returns correct hash value for type HASH_ONLY"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.HASH_ONLY, [rootCA] as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.digest
		si.getValue() instanceof HashedId8
		si.getValue() == new HashedId8(cryptoManager.digest(rootCA.encoded, alg))
	}


	def "Verify that getSignerIdentifier returns first signing certificate from a chain for type SIGNER_CERTIFICATE"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.SIGNER_CERTIFICATE, [enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.certificate
		si.getValue() instanceof SequenceOfCertificate
		((SequenceOfCertificate) si.getValue()).getSequenceValuesAsList()[0] == enrollCert
	}

	def "Verify that getSignerIdentifier returns first signing certificate from a chain for type CERT_CHAIN"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys, rootCAKeys, rootCA)
		KeyPair enrollCertKeys = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys, enrollCAKeys.publicKey, enrollCAKeys.privateKey, enrollCA)

		when:
		SignerIdentifier si = sdg.getSignerIdentifier(SignerIdentifierType.CERT_CHAIN, [enrollCert, enrollCA, rootCA] as Certificate[])
		then:
		si.getType() == SignerIdentifierChoices.certificate
		si.getValue() instanceof SequenceOfCertificate
		List certs = ((SequenceOfCertificate) si.getValue()).getSequenceValuesAsList()
		certs.size() == 2
		certs[0] == enrollCert
		certs[1] == enrollCA
	}
	
	def "Verify that buildCertStore() generates certificate store maps correctly and buildChain generates correct certificate chain"(){
		setup:
		def alg = PublicVerificationKeyChoices.ecdsaNistP256
		KeyPair rootCAKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate rootCA1 = genRootCA(rootCAKeys1)
		HashedId8 rootCA1Id = sdg.getCertID(rootCA1)
		KeyPair rootCAKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate rootCA2 = genRootCA(rootCAKeys2)
		HashedId8 rootCA2Id = sdg.getCertID(rootCA2)
		KeyPair enrollCAKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA1 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys1, rootCAKeys1, rootCA1)
		HashedId8 enrollCA1Id = sdg.getCertID(enrollCA1)
		KeyPair enrollCAKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCA2 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys2, rootCAKeys2, rootCA2)
		HashedId8 enrollCA2Id = sdg.getCertID(enrollCA2)
		KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys1.publicKey, enrollCAKeys1.privateKey, enrollCA1)
		HashedId8 enrollCert1Id = sdg.getCertID(enrollCert1)
		KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
		Certificate enrollCert2 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys2, enrollCAKeys2.publicKey, enrollCAKeys2.privateKey, enrollCA2)
		HashedId8 enrollCert2Id = sdg.getCertID(enrollCert2)

		when: "Verify that buildCertStore generates correct stores"
		Map<HashedId8, Certificate> trustStore = sdg.buildCertStore([rootCA1, rootCA2] as Certificate[])
		Map<HashedId8, Certificate> certStore1 = sdg.buildCertStore([enrollCA1, enrollCA2, enrollCert1] as Certificate[])
		Map<HashedId8, Certificate> certStore2 = sdg.buildCertStore([enrollCA1, enrollCA2, rootCA2] as Certificate[])
		Map<HashedId8, Certificate> signedDataStore1 = sdg.buildCertStore([enrollCA2, enrollCert2] as Certificate[])
		Map<HashedId8, Certificate> signedDataStore2 = sdg.buildCertStore([enrollCert2] as Certificate[])
		then: 
		trustStore.size() == 2
		trustStore.get(rootCA1Id) == rootCA1
		trustStore.get(rootCA2Id) == rootCA2
		
		certStore1.size() == 3
		certStore1.get(enrollCA1Id) == enrollCA1
		certStore1.get(enrollCA2Id) == enrollCA2
		certStore1.get(enrollCert1Id) == enrollCert1
		

		when: "Verify that buildChain constructs a correct chain for a root ca only chain"
		Certificate[] c = sdg.buildChain(rootCA2Id, signedDataStore1, certStore1, trustStore)
		then:
		c.length == 1
		c[0] == rootCA2
		
		when: "Verify that buildChain constructs a chain from all three stores"
		c = sdg.buildChain(enrollCert2Id, signedDataStore1, certStore1, trustStore)
		then:
		c.length == 3
		c[0] == enrollCert2
		c[1] == enrollCA2
		c[2] == rootCA2
		
		when: "Verify that illegal argument is found if signing certificate cannot be found"
		sdg.buildChain(enrollCert2Id, [:], [:], [:])
		then:
		thrown IllegalArgumentException
		
		when: "Verify that illegal argument is found if root certificate cannot be found as trust anchor"
		sdg.buildChain(enrollCert2Id, signedDataStore1, certStore2, [:])
		then:
		thrown IllegalArgumentException
		
		when: "Verify that illegal argument is found if intermediate certificate cannot be found"
		sdg.buildChain(enrollCert2Id, signedDataStore2, [:], trustStore)
		then:
		thrown IllegalArgumentException
	}

	def "Verify that findFromStores finds certificate from stores"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		HashedId8 certId = sdg.getCertID(enrollCA)
		HashedId8 rootCertId = sdg.getCertID(rootCA)
		expect:
		sdg.findFromStores(certId, [(certId):enrollCA], [:], [:]) == enrollCA
		sdg.findFromStores(certId, [:],[(certId):enrollCA], [:]) == enrollCA
		sdg.findFromStores(rootCertId, [:],[:],[(rootCertId):rootCA]) == rootCA
		sdg.findFromStores(certId, [:],[:],[:]) == null
		
		when: "Verify that implicit trust ancor generates IllegalArgumentException"
		sdg.findFromStores(certId, [:],[:],[(certId):enrollCA])
		
		then:
		thrown IllegalArgumentException
		
	}
	
	def "Verify getCertID generates a correct HashedId8"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)

		when:
		HashedId8 certId = sdg.getCertID(rootCA)
		then:
		certId == new HashedId8(cryptoManager.digest(rootCA.getEncoded(), HashAlgorithm.sha256))
	}

	def "Verify that getSignerId throws IllegalArgumentException if SignerIdentifier is self"(){
		when:
		sdg.getSignerId(new SignerIdentifier())
		then:
		thrown IllegalArgumentException
	}

	def "Verify that getSignerId returns the included HashedId8 if type is digest"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		def certId = sdg.getCertID(rootCA)
		expect:
		sdg.getSignerId(new SignerIdentifier(certId)) == certId
	}

	def "Verify that getSignedDataStore returns the HashedId8 of the first certificate if type is certificate"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		def certId = sdg.getCertID(enrollCA)
		expect:
		sdg.getSignerId(new SignerIdentifier(new SequenceOfCertificate([enrollCA, rootCA]))) == certId

	}

	def "Verify that getSignedDataStore returns an empty map if SignerIdentifier is self"(){
		expect:
		sdg.getSignedDataStore(new SignerIdentifier()).size() == 0
	}

	def "Verify that getSignedDataStore returns an empty map if SignerIdentifier is digest"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		expect:
		sdg.getSignedDataStore(new SignerIdentifier(sdg.getCertID(rootCA))).size() == 0
	}

	def "Verify that getSignedDataStore returns a populate map of all certificate if SignerIdentifier is certificate"(){
		setup:
		KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate rootCA = genRootCA(rootCAKeys)
		KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKeyChoices.ecdsaNistP256)
		Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
		when:
		Map<HashedId8, Certificate> result = sdg.getSignedDataStore(new SignerIdentifier(new SequenceOfCertificate([enrollCA, rootCA])))

		then:
		result.size() == 2
		result.get(sdg.getCertID(rootCA)) == rootCA
		result.get(sdg.getCertID(enrollCA)) == enrollCA
	}

	@Unroll
	def "Verify getHashedDataChoice()"(){
		setup:
		sdg_ecdsaNistP256.hashAlgorithm = hashAlg
		expect:
		sdg_ecdsaNistP256.getHashedDataChoice() == choice
		where:
		hashAlg                    | choice
		HashAlgorithm.sha256       | HashedDataChoices.sha256HashedData

	}
}
