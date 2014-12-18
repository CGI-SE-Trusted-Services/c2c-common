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
package org.certificateservices.custom.c2x.its.generator;

import java.security.KeyPair

import org.certificateservices.custom.c2x.its.crypto.CryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType;
import org.certificateservices.custom.c2x.its.generator.AuthorityCertGenerator;
import org.certificateservices.custom.c2x.its.generator.AuthorizationTicketCertGenerator;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorizationTicketCertGeneratorSpec extends Specification {
	
	AuthorizationTicketCertGenerator atg
	@Shared CryptoManager cryptoManager
	
	@Shared KeyPair authorizationCAKeys
	@Shared Certificate authorizationCA
	
	@Shared KeyPair rootCAKeys
	@Shared Certificate rootCA
	
	@Shared KeyPair signKeys
	@Shared KeyPair encKeys 
	
	def setupSpec(){
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		AuthorityCertGenerator acg = new AuthorityCertGenerator(cryptoManager);
				
		rootCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
		
		authorizationCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)		
		authorizationCA = acg.genAuthorizationAuthorityCA("TestAuthorizationCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationCAKeys.getPublic(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, null, rootCAKeys.getPrivate(), rootCA)
		
		signKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		encKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecies_nistp256)
	}
	
	def setup(){
		atg = new AuthorizationTicketCertGenerator(cryptoManager, authorizationCA, authorizationCAKeys.privateKey);
	}
	
	def "Generate Authorization Ticket with a digest as signer info"(){
		when:
		Certificate cert = atg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null)
		then:
		cert.version == 1
		
		cryptoManager.verifyCertificate(cert, authorizationCA);
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.certificate_digest_with_ecdsap256
		cert.signerInfos[0].digest == new HashedId8(cryptoManager.digest(authorizationCA.encoded, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256))
		cert.subjectInfo.subjectType == SubjectType.authorization_ticket
		cert.subjectInfo.subjectName.length == 0
		cert.subjectAttributes.size() == 2
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1 		
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
				
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0

		cert.validityRestrictions.size() == 1
		cert.validityRestrictions[0].startValidity.asDate().time == 1417536852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417536952000L
		
		
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
	}
	
	def "Generate Authorization Ticket with a certificate as signer info"(){
		when:
		Certificate cert = atg.genAuthorizationTicket(SignerInfoType.certificate , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null)
		then:
		cert.version == 1
		
		cryptoManager.verifyCertificate(cert);
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.certificate
		cert.signerInfos[0].certificate != null
		cert.subjectInfo.subjectType == SubjectType.authorization_ticket
		cert.subjectInfo.subjectName.length == 0
		cert.subjectAttributes.size() == 2
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
				
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0

		cert.validityRestrictions.size() == 1
		cert.validityRestrictions[0].startValidity.asDate().time == 1417536852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417536952000L
		
		
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
	}
	

	def "Generate Enrollment Credential with a certificate chain as signer info"(){
		when:
		Certificate cert = atg.genAuthorizationTicket([rootCA, authorizationCA] , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null)
		then:
		cert.version == 1
		
		cryptoManager.verifyCertificate(cert);
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.certificate_chain		
		cert.signerInfos[0].certificateChain.size() == 2
		cert.signerInfos[0].certificateChain[0].getSubjectInfo().getSubjectName() == "TestRootCA".getBytes("UTF-8")
		cert.signerInfos[0].certificateChain[1].getSubjectInfo().getSubjectName() == "TestAuthorizationCA".getBytes("UTF-8")
		cert.subjectInfo.subjectType == SubjectType.authorization_ticket
		cert.subjectInfo.subjectName.length == 0
		cert.subjectAttributes.size() == 2
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
				
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0

		cert.validityRestrictions.size() == 1
		cert.validityRestrictions[0].startValidity.asDate().time == 1417536852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417536952000L
		
		
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
		when: // Verify that only one ca certificate works
		cert =  atg.genAuthorizationTicket([authorizationCA] , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null)
		then:
		cert.version == 1
		
		cryptoManager.verifyCertificate(cert);
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.certificate_chain
		cert.signerInfos[0].certificateChain.size() == 1
		cert.signerInfos[0].certificateChain[0].getSubjectInfo().getSubjectName() == "TestAuthorizationCA".getBytes("UTF-8")
		cert.subjectInfo.subjectType == SubjectType.authorization_ticket
		cert.subjectInfo.subjectName.length == 0
		cert.subjectAttributes.size() == 2
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
				
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0

		cert.validityRestrictions.size() == 1
		cert.validityRestrictions[0].startValidity.asDate().time == 1417536852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417536952000L
		
		
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
	}

	def "Verify that illegal argument exception is thrown for messages with unsupported subject type"(){
		when:
		atg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_other_algorithm , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null)
		then:
		thrown IllegalArgumentException
	}

}
