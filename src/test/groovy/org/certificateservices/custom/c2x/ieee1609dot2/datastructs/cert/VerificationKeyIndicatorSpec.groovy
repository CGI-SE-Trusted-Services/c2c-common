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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for VerificationKeyIndicator
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class VerificationKeyIndicatorSpec extends BaseStructSpec {
	
	@Shared EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
	@Shared PublicVerificationKey pvk = new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, new EccP256CurvePoint(new BigInteger(323),new BigInteger(423)))
	
	@Unroll
	def "Verify that VerificationKeyIndicator is correctly encoded for type #choice"(){
		when:
		def key = new VerificationKeyIndicator(value)
		
		then:
		serializeToHex(key) == encoding
		
		when:
		VerificationKeyIndicator key2 = deserializeFromHex(new VerificationKeyIndicator(), encoding)
		
		then:
		key2.getValue() == value
		key2.choice == choice
		key2.type == choice
		
		where:
		choice                                              | value   | encoding   
		VerificationKeyIndicatorChoices.verificationKey     | pvk     | "808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a7"   
		VerificationKeyIndicatorChoices.reconstructionValue | r       | "8184000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df"      
	}

	
	def "Verify toString"(){
		expect:
		new VerificationKeyIndicator(pvk).toString() == "VerificationKeyIndicator [verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]"
		new VerificationKeyIndicator(r).toString() == "VerificationKeyIndicator [reconstructionValue=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]"
	}

	def coerReferenceEncodingWithBrainPool256Choice = normalizeHex """80 81 80 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00"""

	def coerReferenceEncodingWithBrainPool384Choice = normalizeHex """80 82 31 80 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00"""

	def asdf = normalizeHex """
80 80 80 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00"""



	def "Verify asdf"(){
		when:
		VerificationKeyIndicator vi = deserializeFromHex(new VerificationKeyIndicator(), asdf)
		then:
		vi.toString() == "VerificationKeyIndicator [verificationKey=[ecdsaNistP256=[xonly=0000000000000000000000000000000000000000000000000000000000000000]]]"
	}


	def "Verify externally encoding COER with choice with extension"(){
		when:
		VerificationKeyIndicator vi = deserializeFromHex(new VerificationKeyIndicator(), coerReferenceEncodingWithBrainPool256Choice)
		then:
		serializeToHex(vi) == coerReferenceEncodingWithBrainPool256Choice
		vi.toString() == "VerificationKeyIndicator [verificationKey=[ecdsaBrainpoolP256r1=[xonly=0000000000000000000000000000000000000000000000000000000000000000]]]"
		when:
		vi = deserializeFromHex(new VerificationKeyIndicator(), coerReferenceEncodingWithBrainPool384Choice)
		then:
		serializeToHex(vi) == coerReferenceEncodingWithBrainPool384Choice
		vi.toString() == "VerificationKeyIndicator [verificationKey=[ecdsaBrainpoolP384r1=EccP384CurvePoint [xonly=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]]]"
	}

}
