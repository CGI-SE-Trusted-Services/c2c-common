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
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
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
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SecuredMessageGeneratorSpec extends Specification {
	

	@Shared ITSCryptoManager cryptoManager
	
	@Shared SecuredMessageGenerator sbg_v1
	@Shared SecuredMessageGenerator sbg_v2
	
	@Shared KeyPair authorizationCAKeys
	@Shared Certificate authorizationCA_v1
	@Shared Certificate authorizationCA_v2
	
	@Shared KeyPair rootCAKeys
	@Shared Certificate rootCA_v1
	@Shared Certificate rootCA_v2
	
	
	@Shared KeyPair authorizationTicketKeys
	@Shared Certificate authorizationTicket_v1
	@Shared Certificate authorizationTicket_v2
	
	def setupSpec(){
		// Init cryptomanager
		cryptoManager = new DefaultCryptoManager()
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))

		// Setup PKI Hierarchy
		AuthorityCertGenerator acg_v1 = new AuthorityCertGenerator(Certificate.CERTIFICATE_VERSION_1,cryptoManager);
		AuthorityCertGenerator acg_v2 = new AuthorityCertGenerator(Certificate.CERTIFICATE_VERSION_2,cryptoManager);
				
		
		KeyPair encKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		rootCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		
		rootCAKeys.getPublic().getEncoded()
		rootCAKeys.getPrivate().getEncoded()
		
		rootCA_v1 = acg_v1.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(127)], 1, 0, new Date(1417536852024L), new Date(1417536952031L + 315360000000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
		rootCA_v2 = acg_v2.genRootCA("TestRootCA".getBytes("UTF-8"), [new BigInteger(127)], 1, 0, new Date(1417536852024L), new Date(1417536952031L + 315360000000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), null, null)
	
		authorizationCAKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)		
		authorizationCA_v1 = acg_v1.genAuthorizationAuthorityCA("TestAuthorizationCA".getBytes("UTF-8"), [new BigInteger(127)], 1, 0, new Date(1417536952031L), new Date(1417536952031L + 315350000000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationCAKeys.getPublic(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, null, rootCAKeys.getPrivate(), rootCA_v1)
		authorizationCA_v2 = acg_v2.genAuthorizationAuthorityCA("TestAuthorizationCA".getBytes("UTF-8"), [new BigInteger(127)], 1, 0, new Date(1417536952031L), new Date(1417536952031L + 315350000000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationCAKeys.getPublic(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, null, rootCAKeys.getPrivate(), rootCA_v2)

		// Generate Authorization Ticket
		AuthorizationTicketCertGenerator atcg_v1 = new AuthorizationTicketCertGenerator(Certificate.CERTIFICATE_VERSION_1,cryptoManager, authorizationCA_v1, authorizationCAKeys.getPrivate())
		AuthorizationTicketCertGenerator atcg_v2 = new AuthorizationTicketCertGenerator(cryptoManager, authorizationCA_v2, authorizationCAKeys.getPrivate())
		
		authorizationTicketKeys = cryptoManager.generateKeyPair(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		authorizationTicket_v1 = atcg_v1.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(127)], 1, 0, new Date(), new Date(System.currentTimeMillis() + 28800000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationTicketKeys.getPublic(), null, null)
		authorizationTicket_v2 = atcg_v2.genAuthorizationTicket(SignerInfoType.certificate_digest_with_ecdsap256 , [new BigInteger(127)], 1, 0, new Date(), new Date(System.currentTimeMillis() + 28800000L), null, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, authorizationTicketKeys.getPublic(), PublicKeyAlgorithm.ecies_nistp256, encKeys.getPublic())

		sbg_v1 = new SecuredMessageGenerator(SecuredMessage.PROTOCOL_VERSION_1,Certificate.CERTIFICATE_VERSION_1,cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,authorizationTicket_v1, [authorizationCA_v1] as Certificate[],authorizationTicketKeys.getPrivate(), null,null);
		sbg_v2 = new SecuredMessageGenerator(cryptoManager, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,authorizationTicket_v2, [authorizationCA_v2] as Certificate[],authorizationTicketKeys.getPrivate(), null,null);
	}
	
//	@IgnoreRest
//	def "asdf"(){
//		when:
//		println "Root v2 " + (new HashedId8(rootCA_v2, cryptoManager)) + " : " + Hex.toHexString(rootCA_v2.encoded)
//		println rootCA_v2
//		
//        println "Auth CA v2 " + (new HashedId8(authorizationCA_v2, cryptoManager)) + " : " + Hex.toHexString(authorizationCA_v2.encoded)
//		println authorizationCA_v2
//		
//		println "Auth Ticket v2 " + (new HashedId8(authorizationTicket_v2, cryptoManager)) + " : " + Hex.toHexString(authorizationTicket_v2.encoded)
//		println authorizationTicket_v2
//		
//		def sm = sbg_v2.genSignedCAMMessage(SignerInfoType.certificate_digest_with_ecdsap256, "SomeMessageData".getBytes())
//		println "Singed cam data: " + Hex.toHexString(sm.encoded)
//		println "SignedCAM: " + sm
//		then:
//		true
//	}
	
	@Unroll
	def "Generate version #version Signed CAM Message with and verify that all required fields are set and signature verifies."(){
		when:
		SecuredMessage msg = generator.genSignedCAMMessage(SignerInfoType.certificate_digest_with_ecdsap256, "SomeMessageData".getBytes())
		then:

		
		msg.protocolVersion == version
		if(version == 1){
			msg.securityProfile == MessageType.CAM.securityProfile
		}else{
		    msg.securityProfile == null
		}
		

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 3

		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.digest != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null
		if(version == 1){
		  assert msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		  assert msg.headerFields[2].messageType == MessageType.CAM.getValue()
		}else{
		  assert msg.headerFields[2].headerFieldType == HeaderFieldType.its_aid
		  assert msg.headerFields[2].itsAid.asLong() == SecuredMessageGenerator.ITS_AID_CAM
		}
		
		
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == 	"SomeMessageData"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		when:
		msg = generator.genSignedCAMMessage(SignerInfoType.certificate, "SomeMessageData".getBytes())
		then:
		msg.protocolVersion == version
		if(version == 1){
			msg.securityProfile == MessageType.CAM.securityProfile
		}else{
		    msg.securityProfile == null
		}

		cryptoManager.verifySecuredMessage(msg);
		
		msg.headerFields.size() == 3

		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.certificate != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null
		if(version == 1){
		  assert msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		  assert msg.headerFields[2].messageType == MessageType.CAM.getValue()
		}else{
		  assert msg.headerFields[2].headerFieldType == HeaderFieldType.its_aid
		  assert msg.headerFields[2].itsAid.asLong() == SecuredMessageGenerator.ITS_AID_CAM
		}
		
				
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == 	"SomeMessageData"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		
		where:
		generator  | version    | authorizationTicket
		sbg_v1     | 1          | authorizationTicket_v1
		sbg_v2     | 2          | authorizationTicket_v2
	}
	
	def "Verify that multiple payload works for version 1 of secured CAM message"(){
		when:
		SecuredMessage msg = sbg_v1.genVer1SignedCAMMessage(SignerInfoType.certificate_digest_with_ecdsap256, ["SomeMessageData1".getBytes(),"SomeMessageData2".getBytes()])
		then:
		msg.protocolVersion == 1
		msg.securityProfile == MessageType.CAM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket_v1);

		msg.headerFields.size() == 3

		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.digest != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null

		msg.headerFields[2].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[2].messageType == MessageType.CAM.getValue()


		msg.payloadFields.size() == 2
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == 	"SomeMessageData1"
		msg.payloadFields[1].payloadType == PayloadType.signed
		new String(msg.payloadFields[1].getData()) == 	"SomeMessageData2"

		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
	}

	@Unroll
	def "Generate version #version Signed CAM Unrecognized Certificates Message and verify that all required fields are set and signature verifies."(){
		when:
		SecuredMessage msg = generator.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate, [new HashedId3(Hex.decode("010203")),new HashedId3(Hex.decode("040506"))])
		//println "Signed CAM Unrecognized certificates: " + new String(Hex.encode(msg.getEncoded()))
		
		then:
		msg.protocolVersion == version
		if(version == 1){
			msg.securityProfile == MessageType.CAM.securityProfile
		}else{
		    msg.securityProfile == null
		}

		cryptoManager.verifySecuredMessage(msg, authorizationTicket_v1);
		
		msg.headerFields.size() == 4

		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.certificate != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.request_unrecognized_certificate
		msg.headerFields[2].digests.size() == 2
		if(version == 1){
		  assert msg.headerFields[3].headerFieldType == HeaderFieldType.message_type
		  assert msg.headerFields[3].messageType == MessageType.CAM.getValue()
		}else{
		  assert msg.headerFields[3].headerFieldType == HeaderFieldType.its_aid
		  assert msg.headerFields[3].itsAid.asLong() == SecuredMessageGenerator.ITS_AID_CAM
		}

		
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		msg.payloadFields[0].getData().length == 0
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		
		where:
		generator  | version    | authorizationTicket
		sbg_v1     | 1          | authorizationTicket_v1
		sbg_v2     | 2          | authorizationTicket_v2
	}

	def "Verify that version 2 Signed CAM Unrecognized Certificates Message  certificate, certificate_chain and certificate_digest_with_ecdsap256"(){
		when:
		SecuredMessage msg = sbg_v2.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate, [new HashedId3(Hex.decode("010203")),new HashedId3(Hex.decode("040506"))])
		then:
		msg.protocolVersion == 2
		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.signerInfoType == SignerInfoType.certificate
		msg.headerFields[0].signer.certificate == authorizationTicket_v2
		
		when:
		msg = sbg_v2.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate_digest_with_ecdsap256, [new HashedId3(Hex.decode("010203")),new HashedId3(Hex.decode("040506"))])
		then:
		msg.protocolVersion == 2
		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.signerInfoType == SignerInfoType.certificate_digest_with_ecdsap256
		msg.headerFields[0].signer.digest == new HashedId8(cryptoManager.digest(authorizationTicket_v2.encoded, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256))
		
		when:
		msg = sbg_v2.genSignedCAMUnrecognizedCertificatesMessage(SignerInfoType.certificate_chain, [new HashedId3(Hex.decode("010203")),new HashedId3(Hex.decode("040506"))])
		then:
		msg.protocolVersion == 2
		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.signerInfoType == SignerInfoType.certificate_chain
		msg.headerFields[0].signer.certificateChain.get(0) == authorizationCA_v2
		msg.headerFields[0].signer.certificateChain.get(1) == authorizationTicket_v2
	}
	
	@Unroll
	def "Generate Signed DENM Message and verify that all required fields are set and signature verifies."(){
		when:
		SecuredMessage msg = generator.genSignedDENMMessage(new ThreeDLocation(1, 2, 10), "SomeMessageData".getBytes())
		then:
		//println "Signed DENM: " + new String(Hex.encode(msg.getEncoded()))
		msg.protocolVersion == version
		if(version == 1){
			msg.securityProfile == MessageType.DENM.securityProfile
		}else{
			msg.securityProfile == null
		}
		
		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 4

		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.certificate != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.generation_location
		msg.headerFields[2].generationLocation != null
		if(version == 1){
		  assert msg.headerFields[3].headerFieldType == HeaderFieldType.message_type
		  assert msg.headerFields[3].messageType == MessageType.DENM.getValue()
		}else{
		  assert msg.headerFields[3].headerFieldType == HeaderFieldType.its_aid
		  assert msg.headerFields[3].itsAid.asLong() == SecuredMessageGenerator.ITS_AID_DENM
		}
		
		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == "SomeMessageData"
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		

		
		when:
		msg = generator.genSignedDENMMessage(new ThreeDLocation(1, 2, 10), null)
		then:
		msg.protocolVersion == version
		if(version == 1){
			msg.securityProfile == MessageType.DENM.securityProfile
		}else{
			msg.securityProfile == null
		}

		cryptoManager.verifySecuredMessage(msg, authorizationTicket);
		
		msg.headerFields.size() == 4

		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.certificate != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.generation_location
		msg.headerFields[2].generationLocation != null
		if(version == 1){
		  assert msg.headerFields[3].headerFieldType == HeaderFieldType.message_type
		  assert msg.headerFields[3].messageType == MessageType.DENM.getValue()
		}else{
		  assert msg.headerFields[3].headerFieldType == HeaderFieldType.its_aid
		  assert msg.headerFields[3].itsAid.asLong() == SecuredMessageGenerator.ITS_AID_DENM
		}

		msg.payloadFields.size() == 1
		msg.payloadFields[0].payloadType == PayloadType.signed
		msg.payloadFields[0].getData().length == 0
		
		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
		where:
		generator  | version    | authorizationTicket
		sbg_v1     | 1          | authorizationTicket_v1
		sbg_v2     | 2          | authorizationTicket_v2
	}
	
	def "Verify that multiple payload works for version 1 of secured DENM message"(){
		when:
		SecuredMessage msg = sbg_v1.genVer1SignedDENMMessage(new ThreeDLocation(1, 2, 10), ["SomeMessageData1".getBytes(),"SomeMessageData2".getBytes()])
		then:
		msg.protocolVersion == 1
		msg.securityProfile == MessageType.DENM.securityProfile

		cryptoManager.verifySecuredMessage(msg, authorizationTicket_v1);

		msg.headerFields.size() == 4
		msg.headerFields[0].headerFieldType == HeaderFieldType.signer_info
		msg.headerFields[0].signer.certificate != null
		msg.headerFields[1].headerFieldType == HeaderFieldType.generation_time
		msg.headerFields[1].generationTime != null
		msg.headerFields[2].headerFieldType == HeaderFieldType.generation_location
		msg.headerFields[2].generationLocation != null
		msg.headerFields[3].headerFieldType == HeaderFieldType.message_type
		msg.headerFields[3].messageType == MessageType.DENM.getValue()
	
		msg.payloadFields.size() == 2
		msg.payloadFields[0].payloadType == PayloadType.signed
		new String(msg.payloadFields[0].getData()) == "SomeMessageData1"
		msg.payloadFields[1].payloadType == PayloadType.signed
		new String(msg.payloadFields[1].getData()) == "SomeMessageData2"

		msg.trailerFields.size() == 1
		msg.trailerFields[0].trailerFieldType == TrailerFieldType.signature
		msg.trailerFields[0].signature != null
	}

//	@IgnoreRest
//	def "Interop"(){
//		setup:
//		
//		
//		Certificate c = new Certificate(Hex.decode("0200040a54657374526f6f74434128000003b060341ef10d6baf769bb03a778df5d08f5bdc0d8d82d4d3bca5d9320dc1108d022020017f0901148a8257275685bb00009daddaaac9ce9a25054846f03900b204ee5c2f1241e10fd8528e0d09bef803826fd93c0dd36f68b447e541ff1ecc7a8408a0139ac9e429872012dbfa5804e14a"))
//		//Certificate c = new Certificate(Hex.decode("0201c33fc87aedf5c40f01004c000002b40e820268ebf7b4570d37b005cb2f12e77f3b8bcc6b2a434ce42ba5188ced3301010002a74519cfb66b200312824751ef1e514b24550f29a61d45b70129b65d5fd2bbcc022020017f0901170ec45c170f34dc00001a822967783be803c4ea98c1b10dabf1b539eb299e6095feb1bb0779afbf0433366d707a9d9bf02dbb467dbaa53c68d66b768ae7c106bc103de3d4bb2b0474f0"))
//		
//		println "Cert: " + c
//		
//		println Hex.toHexString(cryptoManager.digest(c.encoded, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256))
//		
//		HashedId8 h = new HashedId8(c, cryptoManager);
//		println "hash: " + h
//		
//		
//		
//		
//	}
	

}
