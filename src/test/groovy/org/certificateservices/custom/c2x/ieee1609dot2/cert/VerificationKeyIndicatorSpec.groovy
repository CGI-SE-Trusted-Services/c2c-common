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
package org.certificateservices.custom.c2x.ieee1609dot2.cert

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

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
	
	@Shared byte[] x = new BigInteger(123).toByteArray()
	@Shared byte[] x2 = new BigInteger(234).toByteArray()
	@Shared EccP256CurvePoint r = new EccP256CurvePoint(EccP256CurvePointChoices.compressedy0,x)
	@Shared PublicVerificationKey pvk = new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, new EccP256CurvePoint(EccP256CurvePointChoices.compressedy0,x2))
	
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
		VerificationKeyIndicatorChoices.verificationKey     | pvk     | "80808200000000000000000000000000000000000000000000000000000000000000ea"   
		VerificationKeyIndicatorChoices.reconstructionValue | r       | "8182000000000000000000000000000000000000000000000000000000000000007b"      
	}

	
	def "Verify toString"(){
		expect:
		new VerificationKeyIndicator(pvk).toString() == "VerificationKeyIndicator [verificationKey=[ecdsaNistP256=[compressedy0=00000000000000000000000000000000000000000000000000000000000000ea]]]"
		new VerificationKeyIndicator(r).toString() == "VerificationKeyIndicator [reconstructionValue=[compressedy0=000000000000000000000000000000000000000000000000000000000000007b]]"
	}
	

}
