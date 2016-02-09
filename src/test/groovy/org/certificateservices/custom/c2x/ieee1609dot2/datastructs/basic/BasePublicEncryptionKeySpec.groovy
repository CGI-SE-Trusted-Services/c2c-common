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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for BasePublicEncryptionKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class BasePublicEncryptionKeySpec extends BaseStructSpec {
	
	EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
	
	@Unroll
	def "Verify that BasePublicEncryptionKey is correctly encoded for type #choice"(){
		when:
		def key = new BasePublicEncryptionKey(choice, r)
		
		then:
		serializeToHex(key) == encoding
		
		when:
		BasePublicEncryptionKey key2 = deserializeFromHex(new BasePublicEncryptionKey(), encoding)
		
		then:
		key2.getValue() == r
		key2.choice == choice
		key2.type == choice
		
		where:
		choice                                              | encoding   
		BasePublicEncryptionKeyChoices.ecdsaNistP256        | "8080000000000000000000000000000000000000000000000000000000000000007b"   
		BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1 | "8180000000000000000000000000000000000000000000000000000000000000007b"      
	
	}
	
	@Unroll
	def "Verify correct algorithms indicator is returned for #algType."(){
		when:
		Algorithm alg = algType.getAlgorithm()
		then:
		alg.getHash() == null
		alg.getSymmetric() == null
		alg.getSignature() == expectedSignature
		alg.getEncryption() == Algorithm.Encryption.ecies
		
		where:
		algType                                              | expectedSignature
		BasePublicEncryptionKeyChoices.ecdsaNistP256         | Algorithm.Signature.ecdsaNistP256
		BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1  | Algorithm.Signature.ecdsaBrainpoolP256r1
	}
	
	def "Verify toString"(){
		expect:
		new BasePublicEncryptionKey(BasePublicEncryptionKeyChoices.ecdsaNistP256, r).toString() == "BasePublicEncryptionKey [ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]"
	}
	

}
