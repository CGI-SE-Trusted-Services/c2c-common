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
	
	EciesNistP256EncryptedKey key1 = new EciesNistP256EncryptedKey(PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH]);
	RecipientInfo ri1 = new RecipientInfo(new HashedId8("123456789".getBytes()), key1);
	RecipientInfo ri2 = new RecipientInfo(new HashedId8("123456788".getBytes()), key1);
	
	HeaderField hfg = new HeaderField(new Time64(new Date(1416407150000L)))
	HeaderField hfgc = new HeaderField(new Time64WithStandardDeviation(new Time64(new Date(1416407150000L)),1))
	HeaderField hfe = new HeaderField(new Time32(new Date(1416407150000L)))
	HeaderField hfl = new HeaderField(new ThreeDLocation(-150,150,150))
	HeaderField hfd = new HeaderField(HeaderFieldType.request_unrecognized_certificate , [new HashedId3("123".getBytes()), new HashedId3("321".getBytes())])
	HeaderField hfm = new HeaderField(4422);
	HeaderField hfs = new HeaderField(new SignerInfo());
	HeaderField hfr = new HeaderField(HeaderFieldType.recipient_info , [ri1,ri2]);
	HeaderField hfenc = new HeaderField(new EncryptionParameters(SymmetricAlgorithm.aes_128_ccm, new byte[12]));

	def "Verify the constructors and getters"(){
		expect:
		hfg.headerFieldType == generation_time
		hfg.generationTime != null
		
		hfgc.headerFieldType == generation_time_confidence
		hfgc.generationTimeWithSdtDeviation != null
		
		hfe.headerFieldType == expiration
		hfe.expireTime != null
		
		hfl.headerFieldType == generation_location
		hfl.generationLocation != null
		
		hfd.headerFieldType == request_unrecognized_certificate
		hfd.digests.size() == 2
		hfd.recipients == null
		
		hfm.headerFieldType == message_type
		hfm.messageType == 4422
		
		hfs.headerFieldType == signer_info
		hfs.signer != null
		
		
		hfr.headerFieldType == recipient_info
		hfr.recipients.size() == 2
		hfr.digests == null
		
		hfenc.headerFieldType == encryption_parameters
		hfenc.encParams != null


		when: 
		new HeaderField(HeaderFieldType.encryption_parameters , [new HashedId3("123".getBytes()), new HashedId3("321".getBytes())])
		then:
		thrown IllegalArgumentException


	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(hfg) == "0000008c27ef92f9c0"
		serializeToHex(hfgc) == "0100008c27ef92f9c001"
		serializeToHex(hfe) == "02092f6d6f"
		serializeToHex(hfl) == "03ffffff6a000000960096"
		serializeToHex(hfd) == "0406313233333231"
		serializeToHex(hfm) == "051146"
		serializeToHex(hfs) == "8000"
		serializeToHex(hfr) == "81809c323334353637383901000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000323334353637383801000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000"
		serializeToHex(hfenc) == "8200000000000000000000000000"
				
	}
	
	def "Verify deserialization"(){
		setup:		
		HeaderField hfg2 = deserializeFromHex(new HeaderField(),"0000008c27ef92f9c0")
		HeaderField hfgc2 = deserializeFromHex(new HeaderField(),"0100008c27ef92f9c001")
		HeaderField hfe2 = deserializeFromHex(new HeaderField(),"02092f6d6f")
		HeaderField hfl2 = deserializeFromHex(new HeaderField(),"03ffffff6a000000960096")
		HeaderField hfd2 = deserializeFromHex(new HeaderField(),"0406313233333231")
		HeaderField hfm2 = deserializeFromHex(new HeaderField(),"051146")
		HeaderField hfs2 = deserializeFromHex(new HeaderField(),"8000")
		HeaderField hfr2 = deserializeFromHex(new HeaderField(),"81809c323334353637383901000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000323334353637383801000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000")
		HeaderField hfenc2 = deserializeFromHex(new HeaderField(),"8200000000000000000000000000")
		expect:
		hfg2.headerFieldType == generation_time
		hfg2.generationTime != null
		
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
		hfg.toString() == "HeaderField [headerFieldType=generation_time, generationTime=Time64 [timeStamp=Wed Nov 19 15:25:50 CET 2014 (154103151000000)]]"
		hfgc.toString() == "HeaderField [headerFieldType=generation_time_confidence, generationTimeWithSdtDeviation=Time64WithStandardDeviation [time=Time64 [timeStamp=Wed Nov 19 15:25:50 CET 2014 (154103151000000)], logStdDev=1]]"
		hfe.toString() == "HeaderField [headerFieldType=expiration, expireTime=Time32 [timeStamp=Wed Nov 19 15:25:50 CET 2014 (154103151)]]"
		hfl.toString() == "HeaderField [headerFieldType=generation_location, generationLocation=ThreeDLocation [encodedElevation=150 ( 150 decimeters), latitude=-150, longitude=150]]"
		hfd.toString() == "HeaderField [headerFieldType=request_unrecognized_certificate, digests=[HashedId3 [hashedId=[49, 50, 51]], HashedId3 [hashedId=[51, 50, 49]]]]"
		hfm.toString() == "HeaderField [headerFieldType=message_type, messageType=4422]"
		hfs.toString() == "HeaderField [headerFieldType=signer_info, signer=SignerInfo [signerInfoType=self]]"
		hfr.toString() == "HeaderField [headerFieldType=recipient_info, recipients=[RecipientInfo [certId=HashedId8 [hashedId=[50, 51, 52, 53, 54, 55, 56, 57]], publicKeyAlgorithm=ecies_nistp256, pkEncryption=EciesNistP256EncryptedKey [publicKeyAlgorithm=ecies_nistp256, symmetricAlgorithm=aes_128_ccm, v=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], c=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], t=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]], RecipientInfo [certId=HashedId8 [hashedId=[50, 51, 52, 53, 54, 55, 56, 56]], publicKeyAlgorithm=ecies_nistp256, pkEncryption=EciesNistP256EncryptedKey [publicKeyAlgorithm=ecies_nistp256, symmetricAlgorithm=aes_128_ccm, v=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], c=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], t=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]]]]"
		hfenc.toString() == "HeaderField [headerFieldType=encryption_parameters, encParams=EncryptionParameters [symmetricAlgorithm=aes_128_ccm, nonce=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]]"
			
	}
}

