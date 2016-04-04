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
package org.certificateservices.custom.c2x.its.datastructs.msg


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EncryptionParameters
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64WithStandardDeviation
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.msg.EciesNistP256EncryptedKey;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType;
import org.certificateservices.custom.c2x.its.datastructs.msg.RecipientInfo;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class HeaderFieldSpec extends BaseStructSpec {
	
	EciesNistP256EncryptedKey key1 = new EciesNistP256EncryptedKey(SecuredMessage.PROTOCOL_VERSION_2, PublicKeyAlgorithm.ecies_nistp256, 
		new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), 
		new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], 
		new byte[EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH]);
	RecipientInfo ri1 = new RecipientInfo(new HashedId8("123456789".getBytes()), key1);
	RecipientInfo ri2 = new RecipientInfo(new HashedId8("123456788".getBytes()), key1);
	
	HeaderField hfg = new HeaderField(2,new Time64(Certificate.CERTIFICATE_VERSION_2 ,new Date(1416407150000L)))
	HeaderField hfgc = new HeaderField(2,new Time64WithStandardDeviation(new Time64(Certificate.CERTIFICATE_VERSION_2 ,new Date(1416407150000L)),1))
	HeaderField hfe = new HeaderField(2,new Time32(Certificate.CERTIFICATE_VERSION_2,new Date(1416407150000L)))
	HeaderField hfl = new HeaderField(2,new ThreeDLocation(-150,150,150))
	HeaderField hfd = new HeaderField(2,HeaderFieldType.request_unrecognized_certificate , [new HashedId3("123".getBytes()), new HashedId3("321".getBytes())])
	HeaderField hfm = new HeaderField(1,4422);
	HeaderField hfi = new HeaderField(2,new IntX(123L));
	HeaderField hfs = new HeaderField(2,new SignerInfo());
	HeaderField hfr = new HeaderField(2,HeaderFieldType.recipient_info , [ri1,ri2]);
	HeaderField hfenc = new HeaderField(2,new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, new byte[12]));

	def "Verify the constructors and getters"(){
		expect:
		hfg.headerFieldType == generation_time
		hfg.generationTime != null
		hfg.protocolVersion == 2
		
		hfgc.headerFieldType == generation_time_confidence
		hfgc.generationTimeWithSdtDeviation != null
		hfgc.protocolVersion == 2
		
		hfe.headerFieldType == expiration
		hfe.expireTime != null
		hfe.protocolVersion == 2
		
		hfl.headerFieldType == generation_location
		hfl.generationLocation != null
		hfl.protocolVersion == 2
		
		hfd.headerFieldType == request_unrecognized_certificate
		hfd.digests.size() == 2
		hfd.recipients == null
		hfd.protocolVersion == 2
		
		hfm.headerFieldType == message_type
		hfm.messageType == 4422
		hfm.protocolVersion == 1
		
		hfi.headerFieldType == its_aid
		hfi.itsAid.asInt() == 123
		hfi.protocolVersion == 2
		
		hfs.headerFieldType == signer_info
		hfs.signer != null
		hfs.protocolVersion == 2
		
		hfr.headerFieldType == recipient_info
		hfr.recipients.size() == 2
		hfr.digests == null
		hfr.protocolVersion == 2
		
		hfenc.headerFieldType == encryption_parameters
		hfenc.encParams != null
		hfenc.protocolVersion == 2


		when: 
		new HeaderField(2, HeaderFieldType.encryption_parameters , [new HashedId3("123".getBytes()), new HashedId3("321".getBytes())])
		then:
		thrown IllegalArgumentException


	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(hfg) == "000001386773d77e40"
		serializeToHex(hfgc) == "010001386773d77e4001"
		serializeToHex(hfe) == "0214794571"
		serializeToHex(hfl) == "03ffffff6a000000960096"
		serializeToHex(hfd) == "0406313233333231"
		serializeToHex(hfm) == "051146"
		serializeToHex(hfi) == "057b"
		serializeToHex(hfs) == "8000"
		serializeToHex(hfr) == "82809432333435363738390100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000003233343536373838010000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
		serializeToHex(hfenc) == "8100000000000000000000000000"
				
	}
	
	def "Verify that invalid protocol version for message type and its_aid throws IllegalArgumentException"(){
		when:
		new HeaderField(2,4422);
		then:
		thrown IllegalArgumentException
		when:
		new HeaderField(1,new IntX(123L));
		then:
		thrown IllegalArgumentException
	}
	

	def "Verify deserialization"(){
		setup:		
		HeaderField hfg2 = deserializeFromHex(new HeaderField(2),"0000008c27ef92f9c0")
		HeaderField hfgc2 = deserializeFromHex(new HeaderField(2),"0100008c27ef92f9c001")
		HeaderField hfe2 = deserializeFromHex(new HeaderField(2),"02092f6d6f")
		HeaderField hfl2 = deserializeFromHex(new HeaderField(2),"03ffffff6a000000960096")
		HeaderField hfd2 = deserializeFromHex(new HeaderField(2),"0406313233333231")
		HeaderField hfm2 = deserializeFromHex(new HeaderField(1),"051146")
		HeaderField hfi2 = deserializeFromHex(new HeaderField(2),"057b")
		HeaderField hfs2 = deserializeFromHex(new HeaderField(2),"8000")
		HeaderField hfr2 = deserializeFromHex(new HeaderField(2),"82809432333435363738390100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000003233343536373838010000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000")
		HeaderField hfenc2 = deserializeFromHex(new HeaderField(2),"8100000000000000000000000000")
		expect:
		hfg2.headerFieldType == generation_time
		hfg2.generationTime != null
		hfg2.protocolVersion == 2
		
		hfgc2.headerFieldType == generation_time_confidence
		hfgc2.generationTimeWithSdtDeviation != null
		
		hfe2.headerFieldType == expiration
		hfe2.expireTime != null
		
		hfl2.headerFieldType == generation_location
		hfl2.generationLocation != null
		
		hfd2.headerFieldType == request_unrecognized_certificate
		hfd2.digests.size() == 2
		hfd2.recipients == null
		
		hfm2.headerFieldType == message_type
		hfm2.messageType == 4422
		
		hfi2.headerFieldType == its_aid
		hfi2.itsAid.asInt() == 123
		
		hfs2.headerFieldType == signer_info
		hfs2.signer != null
		
		
		hfr2.headerFieldType == recipient_info
		hfr2.recipients.size() == 2
		hfr2.digests == null
		
		hfenc2.headerFieldType == encryption_parameters
		hfenc2.encParams != null

	}

	
	def "Verify toString"(){
		expect:
		hfg.toString() == "HeaderField [type=generation_time, generationTime=[Wed Nov 19 15:25:50 CET 2014 (343491953000000)]]"
		hfgc.toString() == "HeaderField [type=generation_time_confidence, generationTimeWithSdtDeviation=[time=[Wed Nov 19 15:25:50 CET 2014 (343491953000000)], logStdDev=1]]"
		hfe.toString() == "HeaderField [type=expiration, expireTime=[Wed Nov 19 15:25:50 CET 2014 (343491953)]]"
		hfl.toString() == "HeaderField [type=generation_location, generationLocation=ThreeDLocation [encodedElevation=150 (150 decimeters), latitude=-150, longitude=150]]"
		hfd.toString() == "HeaderField [type=request_unrecognized_certificate, digests=[313233], [333231]]"
		hfm.toString() == "HeaderField [type=message_type, messageType=4422]"
		hfi.toString() == "HeaderField [type=its_aid, value=[123]]"
		hfs.toString() == "HeaderField [type=signer_info, signer=[type=self]]"
		hfr.toString() == "HeaderField [type=recipient_info, recipients=[certId=[3233343536373839], publicKeyAlgorithm=ecies_nistp256, pkEncryption=[publicKeyAlgorithm=ecies_nistp256, symmetricAlgorithm=aes_128_ccm, v=[eccPointType=x_coordinate_only, x=1], c=00000000000000000000000000000000, t=00000000000000000000000000000000]], [certId=[3233343536373838], publicKeyAlgorithm=ecies_nistp256, pkEncryption=[publicKeyAlgorithm=ecies_nistp256, symmetricAlgorithm=aes_128_ccm, v=[eccPointType=x_coordinate_only, x=1], c=00000000000000000000000000000000, t=00000000000000000000000000000000]]]"
		hfenc.toString() == "HeaderField [type=encryption_parameters, encParams=[symmetricAlgorithm=aes_128_ccm, nonce=000000000000000000000000]]"
			
	}
}

