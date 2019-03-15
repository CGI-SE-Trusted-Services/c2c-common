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

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.Algorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices
import spock.lang.Shared
import spock.lang.Unroll

/**
 * Test for PublicVerificationKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PublicVerificationKeySpec extends BaseStructSpec {
	
	
	@Shared EccP256CurvePoint r_256 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
	@Shared EccP384CurvePoint r_384 = new EccP384CurvePoint(new BigInteger(323),new BigInteger(423))
	
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
		choice.extension == extension
		
		where:
		choice                                            | r      | extension | encoding
		PublicVerificationKeyChoices.ecdsaNistP256        | r_256  | false     | "8084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df"
		PublicVerificationKeyChoices.ecdsaBrainpoolP256r1 | r_256  | false     | "8184000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df"
		PublicVerificationKeyChoices.ecdsaBrainpoolP384r1 | r_384  | true      | "8261840000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a7"

	}
	
	@Unroll
	def "Verify correct algorithms indicator is returned for #algType."(){
		when:
		Algorithm alg = algType.getAlgorithm()
		then:
		alg.getHash() == expectedHash
		alg.getSymmetric() == null
		alg.getSignature() == expectedSignature
		alg.getEncryption() == null
		
		where:
		algType                                              | expectedSignature                            | expectedHash
		PublicVerificationKeyChoices.ecdsaNistP256           | Algorithm.Signature.ecdsaNistP256            | Algorithm.Hash.sha256
		PublicVerificationKeyChoices.ecdsaBrainpoolP256r1    | Algorithm.Signature.ecdsaBrainpoolP256r1     | Algorithm.Hash.sha256
		PublicVerificationKeyChoices.ecdsaBrainpoolP384r1    | Algorithm.Signature.ecdsaBrainpoolP384r1     | Algorithm.Hash.sha384
	}
	
	def "Verify that xonly ecc curve points throws IllegalArgumentException for EccP256CurvePoint"(){
		when:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, new EccP256CurvePoint(new BigInteger(333)))
		then:
		thrown IllegalArgumentException
	}

	def "Verify that xonly ecc curve points throws IllegalArgumentException for EccP384CurvePoint"(){
		when:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaBrainpoolP384r1, new EccP384CurvePoint(new BigInteger(333)))
		then:
		thrown IllegalArgumentException
	}

	def "Verify that ecc curve points of type ecdsaBrainpoolP384r1 byte using EccP256CurvePoint throws IllegalArgumentException"(){
		when:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaBrainpoolP384r1, new EccP256CurvePoint(new BigInteger(333),new BigInteger(433)))
		then:
		def e = thrown IllegalArgumentException
		e.message == "EccP256CurvePoint is not supported for PublicVerificationKey with type ecdsaBrainpoolP384r1."
	}

	def "Verify that ecc curve points of type ecdsaBrainpoolP256r1 byte using EccP384CurvePoint throws IllegalArgumentException"(){
		when:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaBrainpoolP256r1, new EccP384CurvePoint(new BigInteger(333),new BigInteger(433)))
		then:
		def e = thrown IllegalArgumentException
		e.message == "EccP384CurvePoint is not supported for PublicVerificationKey with type ecdsaBrainpoolP256r1."
	}

	def "Verify that ecc curve points of type ecdsaNistP256 byte using EccP384CurvePoint throws IllegalArgumentException"(){
		when:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, new EccP384CurvePoint(new BigInteger(333),new BigInteger(433)))
		then:
		def e = thrown IllegalArgumentException
		e.message == "EccP384CurvePoint is not supported for PublicVerificationKey with type ecdsaNistP256."
	}
	
	def "Verify toString"(){
		expect:
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaNistP256, r_256).toString() == "PublicVerificationKey [ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]"
		new PublicVerificationKey(PublicVerificationKeyChoices.ecdsaBrainpoolP384r1, r_384).toString() == "PublicVerificationKey [ecdsaBrainpoolP384r1=EccP384CurvePoint [uncompressed=[x=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000143, y=0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a7]]]"
	}

}
