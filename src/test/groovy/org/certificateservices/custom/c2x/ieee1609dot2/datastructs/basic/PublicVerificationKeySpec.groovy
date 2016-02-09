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

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.Algorithm
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for PublicVerificationKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PublicVerificationKeySpec extends BaseStructSpec {
	
	
	EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
	
	@Unroll
	def "Verify that PublicVerificationKey is correctly encoded for type #choice"(){
		when:
		def key = new PublicVerificationKey(choice, r)
		
		then:
		serializeToHex(key) == encoding
		
		when:
		PublicVerificationKey key2 = deserializeFromHex(new PublicVerificationKey(), encoding)
		
		then:
		key2.getValue() == r
		key2.choice == choice
		key2.type == choice
		
		where:
		choice                                            | encoding   
		PublicVerificationKeyChoices.ecdsaNistP256        | "8084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df"   
		PublicVerificationKeyChoices.ecdsaBrainpoolP256r1 | "8184000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df"      

		
	}
	
	@Unroll
	def "Verify correct algorithms indicator is returned for #algType."(){
		when:
		Algorithm alg = algType.getAlgorithm()
		then:
		alg.getHash() == Algorithm.Hash.sha256
		alg.getSymmetric() == null
		alg.getSignature() == expectedSignature
		alg.getEncryption() == null
		
		where:
		algType                                              | expectedSignature
		PublicVerificationKeyChoices.ecdsaNistP256           | Algorithm.Signature.ecdsaNistP256
		PublicVerificationKeyChoices.ecdsaBrainpoolP256r1    | Algorithm.Signature.ecdsaBrainpoolP256r1
	}
	
	def "Verify that xonly ecc curve points throws IllegalArgumentException"(){
		when:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, new EccP256CurvePoint(new BigInteger(333)))
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify toString"(){
		expect:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, r).toString() == "PublicVerificationKey [ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]"
	}
	

}
