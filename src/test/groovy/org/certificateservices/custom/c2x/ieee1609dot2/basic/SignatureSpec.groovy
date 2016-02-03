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
package org.certificateservices.custom.c2x.ieee1609dot2.basic

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Signature
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SignatureSpec extends BaseStructSpec {
	
	
	EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
	byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)

	@Unroll
	def "Verify that Signature is correctly encoded for type #choice"(){
		when:
		def sig = new Signature(choice, new EcdsaP256Signature(r,s))
		
		then:
		serializeToHex(sig) == encoding
		
		when:
		Signature sig2 = deserializeFromHex(new Signature(), encoding)
		
		then:
		
		sig2.getValue() == new EcdsaP256Signature(r,s)
		sig2.choice == choice
		sig2.type == choice
		
		where:
		choice                                         | encoding   
		SignatureChoices.ecdsaNistP256Signature        | "8080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"   
		SignatureChoices.ecdsaBrainpoolP256r1Signature | "8180000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"      

		
	}
	
	def "Verify toString"(){
		expect:
		new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s)).toString() == "Signature [ecdsaNistP256Signature=EcdsaP256Signature [r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]"
	}
	

}
