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
package org.certificateservices.custom.c2x.its.datastructs.basic


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EcdsaSignatureSpec extends BaseStructSpec {
	
	
	def "Verify constructors and getters and setters"(){
		when:
		EcdsaSignature es = new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256);
		then:
		es.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		es.r == null
		es.signatureValue == null
		
		when:
		es = new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[32]);
		then:
		es.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		es.r !=  null
		es.signatureValue != null
		when:
		es = new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[31]);
		then:
		thrown IllegalArgumentException
	}

	byte[] testSignature = Hex.decode("1122334455667788990011223344556677889900112233445566778899001122");

	def "Verify serialization of EcdsaSignature"(){
		when: 
		String result = serializeToHex(new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), testSignature));
		then:
		result.length() /2 == 65;
		result.substring(0,2) == "00" // R EccPointType is correct
		result.substring(2,66) == "0000000000000000000000000000000000000000000000000000000000000001" //R EccPoint X Value have been serialized.
		result.substring(66) == "1122334455667788990011223344556677889900112233445566778899001122"
	}
	
	def "Verify deserialization of EcdsaSignature"(){
		when:                                                                                                    // ecc point type // x key value                                                   // Signature Value
		EcdsaSignature result = deserializeFromHex(new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256), "00" + "0000000000000000000000000000000000000000000000000000000000000001" + "1122334455667788990011223344556677889900112233445566778899001122");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		result.r.eccPointType == EccPointType.x_coordinate_only
		result.r.x.toInteger() == 1
		result.signatureValue == testSignature
	}
	

	def "Verify toString"(){
		expect:
		 new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[32]).toString() == "EcdsaSignature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=x_coordinate_only, x=1], signatureValue=0000000000000000000000000000000000000000000000000000000000000000]"
	}

	
}
