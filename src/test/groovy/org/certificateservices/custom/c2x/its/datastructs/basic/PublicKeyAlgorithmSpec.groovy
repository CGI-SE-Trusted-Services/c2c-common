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



import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;

import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm.*;
import static org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PublicKeyAlgorithmSpec extends Specification{
	
	@Unroll
	def "Verify that #publicKeyAlgorithm has bytevalue #bytevalue"(){
		expect:
		publicKeyAlgorithm.byteValue instanceof Integer
		publicKeyAlgorithm.byteValue == bytevalue
		if(fieldSize != 0){
			assert publicKeyAlgorithm.fieldSize == fieldSize
		}
		if(symAlg != null){
			assert publicKeyAlgorithm.relatedSymmetricAlgorithm == symAlg
		}
		where:
		publicKeyAlgorithm             | bytevalue | fieldSize  | symAlg
		ecdsa_nistp256_with_sha256     | 0         | 32L        | null
		ecies_nistp256                 | 1         | 0L         | aes_128_ccm

	}
	
//	def "Verify that UnsupportedOperationException is thrown for a public key with unspecified field size"(){
//		when:
//		ecies_nistp256.fieldSize
//		then:
//		thrown UnsupportedOperationException
//	}
//	
	
	@Unroll
	def "Verify correct algorithms indicator is returned for #algType."(){
		when:
		Algorithm alg = algType.getAlgorithm()
		then:
		alg.getHash() == expectedHash
		alg.getSymmetric() == expectedSymmetric
		alg.getSignature() == expectedSignature
		alg.getEncryption() == expectedEncryption
		
		where:
		algType                                              | expectedSignature                          | expectedHash            | expectedEncryption            | expectedSymmetric
		PublicKeyAlgorithm.ecdsa_nistp256_with_sha256        | Algorithm.Signature.ecdsaNistP256          | Algorithm.Hash.sha256   | null                          | null
		PublicKeyAlgorithm.ecies_nistp256                    | Algorithm.Signature.ecdsaNistP256          | null                    | Algorithm.Encryption.ecies    | Algorithm.Symmetric.aes128Ccm
	}
	def "Verify that UnsupportedOperationException is thrown for a public key with unsupported related symmetric algorithm"(){
		when:
		ecdsa_nistp256_with_sha256.relatedSymmetricAlgorithm
		then:
		thrown UnsupportedOperationException
	}

	@Unroll
	def "Verify that PublicKeyAlgorithm.getByValue returns #publicKeyAlgorithm for #bytevalue"(){
		expect:
		PublicKeyAlgorithm.getByValue( bytevalue) == publicKeyAlgorithm
		where:
		publicKeyAlgorithm             | bytevalue
		ecdsa_nistp256_with_sha256     | 0   
		ecies_nistp256                 | 1 

	}
}
