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

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EcdsaP256Signature
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class EcdsaP256SignatureSpec extends BaseStructSpec {

	byte[] x = new BigInteger(123).toByteArray()
	EccP256CurvePoint r = new EccP256CurvePoint(EccP256CurvePointChoices.xonly,x)
	byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		EcdsaP256Signature sig1 = new EcdsaP256Signature(r,s)
		then:
		serializeToHex(sig1) == "80000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		EcdsaP256Signature sig2 = deserializeFromHex(new EcdsaP256Signature(), "80000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		sig2.getS().length == 32
		new BigInteger(1,sig2.getS()).intValue() == 245
		sig2.getR() == r
		
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new EcdsaP256Signature(r,null)
		then:
		thrown IllegalArgumentException
		when:
		new EcdsaP256Signature(null,s)
		then:
		thrown IllegalArgumentException
	} 
	

	
	def "Verify toString"(){
		expect:
		new EcdsaP256Signature(r,s).toString() == "EcdsaP256Signature [r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]"
	}
	

}
