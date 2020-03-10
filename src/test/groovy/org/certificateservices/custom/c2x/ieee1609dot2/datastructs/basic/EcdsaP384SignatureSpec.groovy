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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature

/**
 * Test for EcdsaP384Signature
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class EcdsaP384SignatureSpec extends BaseStructSpec {


	EccP384CurvePoint r = new EccP384CurvePoint(new BigInteger(123))
	byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),48)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		EcdsaP384Signature sig1 = new EcdsaP384Signature(r,s)
		then:
		serializeToHex(sig1) == "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5"
		when:
		EcdsaP384Signature sig2 = deserializeFromHex(new EcdsaP384Signature(), "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5")
		then:
		sig2.getS().length == 48
		new BigInteger(1,sig2.getS()).intValue() == 245
		sig2.getR() == r
		
		
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new EcdsaP384Signature(r,null)
		then:
		thrown IOException
		when:
		new EcdsaP384Signature(null,s)
		then:
		thrown IOException
	} 
	

	
	def "Verify toString"(){
		expect:
		new EcdsaP384Signature(r,s).toString() == "EcdsaP384Signature [r=[xonly=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b], s=0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5]"
	}
	

}
