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

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorityCertGeneratorSpec extends Specification {
	
	AuthorityCertGenerator acg
	@Shared CryptoManager cryptoManager
	@Shared KeyPair rootCAKeys
	@Shared KeyPair signKeys
	@Shared KeyPair encKeys 
	
	def setupSpec(){
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		rootCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		signKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		encKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecies_nistp256)
	}
	
	def setup(){

		acg = new AuthorityCertGenerator(cryptoManager)
	}
	
	def "Generate RootCA with Encryption Key and Geographic region and verify that all attributes are set."(){
		setup:		
		GeographicRegion geoRegion = new GeographicRegion(new CircularRegion(new TwoDLocation(15, 18), 5000))
		
		when:
		Certificate cert = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), geoRegion, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), signKeys.getPrivate(), PublicKeyAlgorithm.ecies_nistp256, encKeys.getPublic())
		then:
		cert.version == 1
		
		cryptoManager.verifyCertificate(cert);
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.self
		cert.subjectInfo.subjectType == SubjectType.root_ca
		cert.subjectInfo.subjectName == "TestRootCA".getBytes("UTF-8")
		cert.subjectAttributes.size() == 4
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1 		
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
		
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.encryption_key
		cert.subjectAttributes[1].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		cert.subjectAttributes[1].publicKey.supportedSymmAlg == SymmetricAlgorithm.aes_128_ccm
		cert.subjectAttributes[1].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[1].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecies_nistp256, cert.subjectAttributes[1].publicKey.publicKey) == encKeys.publicKey
		
		cert.subjectAttributes[2].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[2].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[2].subjectAssurance.confidenceLevel == 0
		
		cert.subjectAttributes[3].subjectAttributeType == SubjectAttributeType.its_aid_list
		cert.subjectAttributes[3].itsAidList.size() == 2
		cert.subjectAttributes[3].itsAidList[0].value == new BigInteger(1234)
		cert.subjectAttributes[3].itsAidList[1].value == new BigInteger(2345)

		cert.validityRestrictions.size() == 2
		cert.validityRestrictions[0].startValidity.asDate().time == 1417536852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417536952000L
		
		cert.validityRestrictions[1].validityRestrictionType == ValidityRestrictionType.region
		cert.validityRestrictions[1].region.regionType == RegionType.circle
		cert.validityRestrictions[1].region.circularRegion.center.latitude == 15
		cert.validityRestrictions[1].region.circularRegion.center.longitude == 18
		cert.validityRestrictions[1].region.circularRegion.radius == 5000
		
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
	}
	
	def "Generate RootCA without Encryption Key and Geographic region and verify that all other attributes are set."(){
		
		when:
		Certificate cert = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), signKeys.getPrivate(), null, null)
		then:
		cryptoManager.verifyCertificate(cert);
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.self
		cert.subjectInfo.subjectType == SubjectType.root_ca
		cert.subjectInfo.subjectName == "TestRootCA".getBytes("UTF-8")
		cert.subjectAttributes.size() == 3
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
		
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0
		
		cert.subjectAttributes[2].subjectAttributeType == SubjectAttributeType.its_aid_list
		cert.subjectAttributes[2].itsAidList.size() == 2
		cert.subjectAttributes[2].itsAidList[0].value == new BigInteger(1234)
		cert.subjectAttributes[2].itsAidList[1].value == new BigInteger(2345)

		cert.validityRestrictions.size() == 1
		cert.validityRestrictions[0].startValidity.asDate().time == 1417536852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417536952000L
				
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
	}
	

		def "Generate Authorization Authority and verify that it is signed by the Root CA"(){
		setup:
		Certificate rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
		
		when:
		Certificate cert = acg.genAuthorizationAuthorityCA("TestAuthorizationAuthority".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417636852024L), new Date(1417636952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null, rootCAKeys.getPrivate(), rootCA)
		then:
		cert.version == 1
		
		cryptoManager.verifyCertificate(cert);
		
		cert.signerInfos.size() == 1
		cert.signerInfos[0].signerInfoType == SignerInfoType.certificate
		cert.subjectInfo.subjectType == SubjectType.authorization_authority
		cert.subjectInfo.subjectName == "TestAuthorizationAuthority".getBytes("UTF-8")
		cert.subjectAttributes.size() == 3
		cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
		cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
		cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
				
		cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
		cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
		cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0

		cert.subjectAttributes[2].subjectAttributeType == SubjectAttributeType.its_aid_list
		cert.subjectAttributes[2].itsAidList.size() == 2
		cert.subjectAttributes[2].itsAidList[0].value == new BigInteger(1234)
		cert.subjectAttributes[2].itsAidList[1].value == new BigInteger(2345)
		
		cert.validityRestrictions.size() == 1
		cert.validityRestrictions[0].startValidity.asDate().time == 1417636852000L
		cert.validityRestrictions[0].endValidity.asDate().time == 1417636952000L
				
		cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		cert.signature.ecdsaSignature != null
		
	}
		
	def "Generate Enrollment Authority and verify that it is signed by the Root CA"(){
			setup:
			Certificate rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
			
			when:
			Certificate cert = acg.genEnrollmentAuthorityCA("TestEnrollmentAuthority".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417736852024L), new Date(1417736952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null, rootCAKeys.getPrivate(), rootCA)
			then:
			cert.version == 1
			
			cryptoManager.verifyCertificate(cert);
			
			cert.signerInfos.size() == 1
			cert.signerInfos[0].signerInfoType == SignerInfoType.certificate
			cert.subjectInfo.subjectType == SubjectType.enrollment_authority
			cert.subjectInfo.subjectName == "TestEnrollmentAuthority".getBytes("UTF-8")
			cert.subjectAttributes.size() == 3
			cert.subjectAttributes[0].subjectAttributeType == SubjectAttributeType.verification_key
			cert.subjectAttributes[0].publicKey.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
			cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_0 || cert.subjectAttributes[0].publicKey.publicKey.eccPointType == EccPointType.compressed_lsb_y_1
			cryptoManager.decodeEccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, cert.subjectAttributes[0].publicKey.publicKey) == signKeys.publicKey
					
			cert.subjectAttributes[1].subjectAttributeType == SubjectAttributeType.assurance_level
			cert.subjectAttributes[1].subjectAssurance.assuranceLevel == 1
			cert.subjectAttributes[1].subjectAssurance.confidenceLevel == 0
			
			cert.subjectAttributes[2].subjectAttributeType == SubjectAttributeType.its_aid_list
			cert.subjectAttributes[2].itsAidList.size() == 2
			cert.subjectAttributes[2].itsAidList[0].value == new BigInteger(1234)
			cert.subjectAttributes[2].itsAidList[1].value == new BigInteger(2345)
	
			cert.validityRestrictions.size() == 1
			cert.validityRestrictions[0].startValidity.asDate().time == 1417736852000L
			cert.validityRestrictions[0].endValidity.asDate().time == 1417736952000L
					
			cert.signature.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
			cert.signature.ecdsaSignature != null
			
	}

	def "Verify illegal subjec type no root ca and CA certificate null throws illegal argument exception"(){
		when:
		acg.genCA(SubjectType.authorization_authority, "TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, signKeys.getPublic(), null, null, signKeys.getPrivate(), null)
		then:
		thrown IllegalArgumentException
	}

}
