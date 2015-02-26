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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.crypto.CryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType;
import org.certificateservices.custom.c2x.its.datastructs.msg.MessageType;
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerFieldType;
import org.certificateservices.custom.c2x.its.generator.AuthorityCertGenerator;
import org.certificateservices.custom.c2x.its.generator.EnrollmentCredentialCertGenerator;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredMessageGeneratorSpec extends Specification {
	

	@Shared CryptoManager cryptoManager
	
	SecuredMessageGenerator sbg
	
	@Shared KeyPair authorizationCAKeys
	@Shared Certificate authorizationCA
	
	@Shared KeyPair rootCAKeys
	@Shared Certificate rootCA
	
	
	@Shared KeyPair authorizationTicketKeys
	@Shared Certificate authorizationTicket
	
	def setupSpec(){
		// Init crytomanager
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
		
		// Setup PKI Hierarchy
		AuthorityCertGenerator acg = new AuthorityCertGenerator(cryptoManager);
				
		rootCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		rootCA = acg.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
		
		authorizationCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)		
		authorizationCA = acg.genAuthorizationAuthorityCA("TestAuthorizationCA".getBytes("UTF-8"), [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationCAKeys.getPublic(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, null, rootCAKeys.getPrivate(), rootCA)
		
		// Generate Authorization Ticket
		AuthorizationTicketCertGenerator atcg = new AuthorizationTicketCertGenerator(cryptoManager, authorizationCA, authorizationCAKeys.getPrivate())
		
		authorizationTicketKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		authorizationTicket = atcg.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(1234), new BigInteger(2345)], 1, 0, new Date(1417536852024L), new Date(1417536952031L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationTicketKeys.getPublic(), null, null)
	}
	
	def setup(){
		sbg = new SecuredMessageGenerator(cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,authorizationTicket, authorizationTicketKeys.getPrivate(), null,null);
	}
	
	def "Generate Signed CAM Message with and verify that all required fields are set and signature verifies."(){
		when:
		SecuredMessage msg = sbg.genSignedCAMMessage(SignerInfoType.certificate_digest_with_ecdsap256, "SomeMessageData".getBytes())
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.CAM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 3

		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[1].messageType == MessageType.CAM.getValue()
		msg.headerFields[2].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[2].signer.digest != null
		
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == 	"SomeMessageData"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		when:
		msg = sbg.genSignedCAMMessage(SignerInfoType.certificate, "SomeMessageData".getBytes())
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.CAM.securityProfile

		cryptoManager.verifySecuredMessage(msg);
		
		msg.headerFields.size() == 3


		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[1].messageType == MessageType.CAM.getValue()
		msg.headerFields[2].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[2].signer.certificate != null
				
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == 	"SomeMessageData"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		when:
		msg = sbg.genSignedCAMMessage(SignerInfoType.certificate_digest_with_ecdsap256, ["SomeMessageData1".getBytes(),"SomeMessageData2".getBytes()])
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.CAM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 3

		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[1].messageType == MessageType.CAM.getValue()
		msg.headerFields[2].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[2].signer.digest != null
				
		msg.payloadFields.size() == 2
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == 	"SomeMessageData1"
		msg.payloadFields[1].payloadType == PayloadType.signed
		new String(msg.payloadFields[1].getData()) == 	"SomeMessageData2"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
	}
	

	def "Generate Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies."(){
		when:
		SecuredMessage msg = sbg.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate_digest_with_ecdsap256, [new HashedId3(Hex.decode("010203")),new HashedId3(Hex.decode("040506"))])
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.CAM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 4

		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.request_unrecognized_certificate
		msg.headerFields[1].digests.size() == 2
		msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[2].messageType == MessageType.CAM.getValue()
		msg.headerFields[3].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[3].signer.digest != null
		
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		msg.payloadFields[0].getData().length == 0
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
	}

	def "Generate Signed DENM Message and verify that all required fields are set and signature verifies."(){
		when:
		SecuredMessage msg = sbg.genSignedDENMMessage(new ThreeDLocation(1, 2, 10), "SomeMessageData".getBytes())
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.DENM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 4

		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_location
		msg.headerFields[1].generationLocation != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[2].messageType == MessageType.DENM.getValue()
		msg.headerFields[3].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[3].signer.certificate != null

		
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == "SomeMessageData"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		when:
		msg = sbg.genSignedDENMMessage(new ThreeDLocation(1, 2, 10), ["SomeMessageData1".getBytes(),"SomeMessageData2".getBytes()])
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.DENM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 4
		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_location
		msg.headerFields[1].generationLocation != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[2].messageType == MessageType.DENM.getValue()
		msg.headerFields[3].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[3].signer.certificate != null

		msg.payloadFields.size() == 2
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == "SomeMessageData1"
		msg.payloadFields[1].payloadType == PayloadType.signed
		new String(msg.payloadFields[1].getData()) == "SomeMessageData2"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		when:
		msg = sbg.genSignedDENMMessage(new ThreeDLocation(1, 2, 10), null)
		then:
		msg.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		msg.securityProfile == MessageType.DENM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 4

		msg.headerFields[0].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[0].generationTime != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_location
		msg.headerFields[1].generationLocation != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[2].messageType == MessageType.DENM.getValue()
		msg.headerFields[3].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[3].signer.certificate != null

		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		msg.payloadFields[0].getData().length == 0
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
	}

}
