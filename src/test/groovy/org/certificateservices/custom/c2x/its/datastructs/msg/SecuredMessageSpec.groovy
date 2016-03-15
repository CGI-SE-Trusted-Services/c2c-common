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
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature
import org.certificateservices.custom.c2x.its.datastructs.basic.EncryptionParameters
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.ThreeDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64
import org.certificateservices.custom.c2x.its.datastructs.basic.Time64WithStandardDeviation
import org.certificateservices.custom.c2x.its.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration.Unit;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload;
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerField;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SecuredMessageSpec extends BaseStructSpec {
	
	def hfSignerInfo = new HeaderField(new SignerInfo(new HashedId8("87654321".getBytes())))
	def hfGenTime = new HeaderField(new Time64(new Date(1416407150000L)))
	def hfmt= new HeaderField(2)

	def plSigned = new Payload(PayloadType.signed, new byte[0]);
	def plSigExt = new Payload();
	
	byte[] testSignature = Hex.decode("1122334455667788990011223344556677889900112233445566778899001122");
	Signature signature =new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.compressed_lsb_y_0, new BigInteger(1)), testSignature))
	def tf1 = new TrailerField(signature)
	
	SecuredMessage sm1 = new SecuredMessage(SecuredMessage.DEFAULT_SECURITY_PROFILE,[hfSignerInfo,hfGenTime,hfmt],[plSigned]);
	SecuredMessage sm2 = new SecuredMessage(2,3,[hfSignerInfo,hfGenTime,hfmt],[plSigned,plSigExt],[tf1]);
	SecuredMessage sm3 = new SecuredMessage(Hex.decode("020316800138373635343332310000008c27ef92f9c0050002030100034301000200000000000000000000000000000000000000000000000000000000000000011122334455667788990011223344556677889900112233445566778899001122"));
	
	def "Verify the constructors, getters and attachSignature"(){
		expect:
		sm1.protocolVersion == SecuredMessage.DEFAULT_PROTOCOL
		sm1.securityProfile == SecuredMessage.DEFAULT_SECURITY_PROFILE
		sm1.headerFields.size() == 3
		sm1.payloadFields.size() == 1
		sm1.trailerFields != null
		
		sm2.protocolVersion == 2
		sm2.securityProfile == 3
		sm2.headerFields.size() == 3
		sm2.payloadFields.size() == 2
		sm2.trailerFields.size() == 1
		
		sm3.protocolVersion == 2
		sm3.securityProfile == 3
		sm3.headerFields.size() == 3
		sm3.payloadFields.size() == 2
		sm3.trailerFields.size() == 1
		
		when:
		sm1.attachSignature(signature)
		
		then:
		sm1.trailerFields.size() == 1

	}

	
	def "Verify serialization"(){
		expect:
		serializeToHex(sm1) == "010016800138373635343332310000008c27ef92f9c0050002020100"
		serializeToHex(sm2) == "020316800138373635343332310000008c27ef92f9c0050002030100034301000200000000000000000000000000000000000000000000000000000000000000011122334455667788990011223344556677889900112233445566778899001122"				
	}
	
	def "Verify deserialization"(){
		setup:		
		SecuredMessage sm22 = deserializeFromHex(new SecuredMessage(),"020316800138373635343332310000008c27ef92f9c0050002030100034301000200000000000000000000000000000000000000000000000000000000000000011122334455667788990011223344556677889900112233445566778899001122")
		
		expect:
		
		sm22.protocolVersion == 2
		sm22.securityProfile == 3
		sm22.headerFields.size() == 3
		sm22.payloadFields.size() == 2
		sm22.trailerFields.size() == 1
	}
	

	
	def "Verify toString"(){
		expect:
		sm2.toString() == "SecuredMessage [protocolVersion=2, securityProfile=3, headerFields=[HeaderField [headerFieldType=signer_info, signer=SignerInfo [signerInfoType=certificate_digest_with_ecdsap256, digest=HashedId8 [hashedId=[56, 55, 54, 53, 52, 51, 50, 49]]]], HeaderField [headerFieldType=generation_time, generationTime=Time64 [timeStamp=Wed Nov 19 15:25:50 CET 2014 (154103151000000)]], HeaderField [headerFieldType=message_type, messageType=2]], payloadFields=[Payload [payloadType=signed, data=[]], Payload [payloadType=signed_external]], trailerFields=[TrailerField [trailerFieldType=signature, signature=Signature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=EcdsaSignature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, compressedEncoding=null, eccPointType=compressed_lsb_y_0], signatureValue=[17, 34, 51, 68, 85, 102, 119, -120, -103, 0, 17, 34, 51, 68, 85, 102, 119, -120, -103, 0, 17, 34, 51, 68, 85, 102, 119, -120, -103, 0, 17, 34]]]]]]"
	}
	
	def "Verify getEncoded"(){
		expect:
		new String(Hex.encode(sm2.getEncoded())) == "020316800138373635343332310000008c27ef92f9c0050002030100034301000200000000000000000000000000000000000000000000000000000000000000011122334455667788990011223344556677889900112233445566778899001122"
	}
	
	def "Verify that it is possible to parse a SecureMessage generate by interoperability site at https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/"(){
		when:
		SecuredMessage sm = new SecuredMessage(externalSecureMessage1)

		then:
		sm.protocolVersion == 1
		sm.securityProfile == 1 
		sm.headerFields.size() == 3
		sm.payloadFields.size() == 1
		sm.trailerFields.size() == 1
	}
	
	
	static final def externalSecureMessage1 = Hex.decode("010181038002010901A8ED6DF65B0E6D6A0100809400000418929DB6A9E452223062C52028E956BF9874E0A40D21D5F9F56564F39C5DD187C922F2E5F0630373879A43393373B9F6205BF01FBD9C1F113165C291C376F535010004EABA91A915D81807E910FD292D99DF8B401EED88CF7F031412D5ED9905F9996469798C412FC8F7237A3AB3469795E2DEF5E1B783EA4F6B6A2359D21772B2EA9D0200210AC040800101C0408101010F01099EB20109B1270003040100960000004B2E6D0D0EE9BC4AD9CD087B601E9AF06031995443D652763455FBB794B33982889260740EF64CFA8C6808A58F98E06CE42A1E9C22A0785D7242647F7895ABFC0000009373931CD7580500021E011C983E690E5F6D755BD4871578A9427E7BC383903DC7DA3B560384013643010000FE8566BEA87B39E6411F80226E792D6E01E77B598F2BB1FCE7F2DD441185C07CEF0573FBFB9876B99FE811486F6F5D499E6114FC0724A67F8D71D2A897A7EB34")
}

