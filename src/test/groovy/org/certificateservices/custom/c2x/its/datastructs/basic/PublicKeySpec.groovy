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
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PublicKeySpec extends BaseStructSpec {
	
	EccPoint publicKey = new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1))
	
	def "Verify constructors and getters and setters"(){
		when:
		PublicKey pk = new PublicKey();
		then:
		pk.publicKeyAlgorithm == null
		pk.publicKey == null
		pk.supportedSymmAlg == null
		when:
		pk = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, publicKey);
		then:
		pk.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		pk.publicKey == publicKey
		pk.supportedSymmAlg == null
		when:
		pk = new PublicKey(PublicKeyAlgorithm.ecies_nistp256, publicKey,SymmetricAlgorithm.aes_128_ccm);
		then:
		pk.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		pk.publicKey == publicKey
		pk.supportedSymmAlg == SymmetricAlgorithm.aes_128_ccm
		when:
		pk = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, publicKey,SymmetricAlgorithm.aes_128_ccm);
		then:
		pk.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		pk.publicKey == publicKey
		pk.supportedSymmAlg == null
	}


	def "Verify serialization of PublicKey"(){
		when: "Verify ecdsa_nistp256_with_sha256 serialization"
		String result = serializeToHex(new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, publicKey));
		then:
		result.length() /2 == 34;
		result.substring(0,2) == "00" // Public Key Algorithm is correct
		result.substring(2,4) == "00" // EccPointType is correct
		result.substring(4) == "0000000000000000000000000000000000000000000000000000000000000001" // X Value have been serialized.
		when: "Verify ecies_nistp256 serialization"
		result = serializeToHex(new PublicKey(PublicKeyAlgorithm.ecies_nistp256, publicKey, SymmetricAlgorithm.aes_128_ccm));
	    then:
		result.length() /2 == 35;
		result.substring(0,2) == "01" // Public Key Algorithm is correct
		result.substring(2,4) == "00" // Supported Symmetrinc Algorithm is correct
		result.substring(2,4) == "00" // EccPointType is correct
		result.substring(6) == "0000000000000000000000000000000000000000000000000000000000000001" // X Value have been serialized.
		
	}
	
	def "Verify deserialization of PublicKey"(){
		when: "Verify ecdsa_nistp256_with_sha256 deserialization"  
		                                                  // pk alg // ecc point type // x key value   
		PublicKey result = deserializeFromHex(new PublicKey(), "00" + "00" + "0000000000000000000000000000000000000000000000000000000000000001");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256
		result.publicKey.eccPointType == EccPointType.x_coordinate_only
		result.publicKey.x.toInteger() == 1
		result.supportedSymmAlg == null
		/*// This part won't run due to non specified field size of public key in table 2.
		when: "Verify ecies_nistp256 deserialization"                                      
		                                       // pk alg // symAlg // ecc point type // x key value                                                    // y key value
		result = deserializeFromHex(new PublicKey(), "01" + "00" +  "04" + "0000000000000000000000000000000000000000000000000000000000000001" + "0000000000000000000000000000000000000000000000000000000000000002");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		result.publicKey.eccPointType == EccPointType.uncompressed
		result.publicKey.x.toInteger() == 1
		result.publicKey.y.toInteger() == 2
		result.supportedSymmAlg == SymmetricAlgorithm.aes_128_ccm
		*/
	}
	
	def "Verify hashCode and equals"(){
		setup:
		def o1  = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, publicKey);
		def o2  = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, publicKey);
		def o3  = new PublicKey(PublicKeyAlgorithm.ecies_nistp256, publicKey, SymmetricAlgorithm.aes_128_ccm);
		def o4  = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecies_nistp256, EccPointType.uncompressed, new BigInteger(1), new BigInteger(2)));
		expect:
		o1 == o2
		o1 != o3
		o1 != o4
		o1.hashCode() == o2.hashCode()
		o1.hashCode() != o3.hashCode()
		o1.hashCode() != o4.hashCode()

	}
	
	def "Verify toString"(){
		expect:
		 new PublicKey(PublicKeyAlgorithm.ecies_nistp256, publicKey, SymmetricAlgorithm.aes_128_ccm).toString() == 
		 """PublicKey [publicKeyAlgorithm=ecies_nistp256, publicKey=[eccPointType=x_coordinate_only, x=1], supportedSymmAlg=aes_128_ccm]"""
	}
	

}
