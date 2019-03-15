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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator
import spock.lang.Shared
import spock.lang.Unroll

/**
 * Test for Signature
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SignatureSpec extends BaseStructSpec {
	
	
	@Shared EccP256CurvePoint r_32 = new EccP256CurvePoint(new BigInteger(123))
	@Shared byte[] s_32 = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)

	@Shared EccP384CurvePoint r_48 = new EccP384CurvePoint(new BigInteger(123))
	@Shared byte[] s_48 = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),48)

	@Unroll
	def "Verify that Signature is correctly encoded for type #choice"(){
		when:
		def sig = new Signature(choice, getSignature(r,s))
		
		then:
		serializeToHex(sig) == encoding
		
		when:
		Signature sig2 = deserializeFromHex(new Signature(), encoding)
		
		then:
		
		sig2.getValue() == getSignature(r,s)
		sig2.choice == choice
		sig2.type == choice
		choice.extension == extension
		
		where:
		choice                                         | r    | s    | extension | encoding
		SignatureChoices.ecdsaNistP256Signature        | r_32 | s_32 | false     | "8080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		SignatureChoices.ecdsaBrainpoolP256r1Signature | r_32 | s_32 | false     | "8180000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		SignatureChoices.ecdsaBrainpoolP384r1Signature | r_48 | s_48 | true      | "82618000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5"

		
	}
	
	def "Verify toString"(){
		expect:
		new Signature(SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r_32,s_32)).toString() == "Signature [ecdsaNistP256Signature=EcdsaP256Signature [r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]"
	}

	private def getSignature(def r, byte[] s){
		if(r instanceof EccP256CurvePoint){
			return new EcdsaP256Signature(r,s)
		}
		if(r instanceof EccP384CurvePoint){
			return new EcdsaP384Signature(r,s)
		}
		assert false
	}


	def coerReferenceEncodingWithNist256 = """80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00""".replaceAll("\n","").replaceAll(" ","").toLowerCase()

	def "Verify externally encoding COER with choice with extension"(){
		when:
		Signature s = deserializeFromHex(new Signature(), coerReferenceEncodingWithNist256)
		then:
		serializeToHex(s) == coerReferenceEncodingWithNist256
	}
}
