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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for PublicEncryptionKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PublicEncryptionKeySpec extends BaseStructSpec {

	byte[] x = new BigInteger(123).toByteArray()
	EccP256CurvePoint p = new EccP256CurvePoint(EccP256CurvePointChoices.compressedy0,x)
	BasePublicEncryptionKey pubKey = new BasePublicEncryptionKey(BasePublicEncryptionKeyChoices.ecdsaNistP256, p)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PublicEncryptionKey pk1 = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey)
		then:
		serializeToHex(pk1) == "008082000000000000000000000000000000000000000000000000000000000000007b"
		when:
		PublicEncryptionKey pk2 = deserializeFromHex(new PublicEncryptionKey(), "008082000000000000000000000000000000000000000000000000000000000000007b")
		then:
		pk2.getSupportedSymmAlg() == SymmAlgorithm.aes128Ccm
		pk2.getPublicKey() == pubKey
		
		
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		serializeToHex(new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,null))
		then:
		thrown IOException
		when:
		serializeToHex(new PublicEncryptionKey(null,pubKey))
		then:
		thrown IOException
	} 
	

	
	def "Verify toString"(){
		expect:
		new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey).toString() == "PublicEncryptionKey [supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy0=000000000000000000000000000000000000000000000000000000000000007b]]]"
	}
	

}
