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
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SignatureSpec extends BaseStructSpec {
	
	
	def "Verify constructors and getters and setters"(){
		when:
		Signature s = new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256));
		then:
		s.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		s.ecdsaSignature != null
		
		when:
		s = new Signature(PublicKeyAlgorithm.ecies_nistp256,new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256));		
		then:
		thrown IllegalArgumentException
	}

	byte[] testSignature = Hex.decode("1122334455667788990011223344556677889900112233445566778899001122");

	def "Verify serialization of Signature"(){
		when: 
		String result = serializeToHex(new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.compressed_lsb_y_0, new BigInteger(1)), testSignature)));
		then:
		result.length() /2 == 66;
		result.substring(0,2) == "00" // public algorithm is correct
		result.substring(2,4) == "02" // R EccPointType is correct
		result.substring(4,68) == "0000000000000000000000000000000000000000000000000000000000000001" //R EccPoint X Value have been serialized.
		result.substring(68) == "1122334455667788990011223344556677889900112233445566778899001122"
	}
	
	def "Verify deserialization ofSignature"(){
		when:                                        // public alg type// ecc point type // x key value                                                   // Signature Value
		Signature result = deserializeFromHex(new Signature(), "00" + "02" + "0000000000000000000000000000000000000000000000000000000000000001" + "1122334455667788990011223344556677889900112233445566778899001122");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		result.ecdsaSignature.r.eccPointType == EccPointType.compressed_lsb_y_0
		result.ecdsaSignature.r.compressedEncoding.length == 33
		result.ecdsaSignature.signatureValue == testSignature
	}
	

	def "Verify toString"(){
		expect:
		 new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.compressed_lsb_y_0, new BigInteger(1)), testSignature)).toString() == "Signature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=[publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=[eccPointType=compressed_lsb_y_0, compressedEncoding=null], signatureValue=1122334455667788990011223344556677889900112233445566778899001122]]"
	}

}
