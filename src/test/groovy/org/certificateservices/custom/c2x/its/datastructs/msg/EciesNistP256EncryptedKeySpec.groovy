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
package org.certificateservices.custom.c2x.its.datastructs.msg


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.msg.EciesNistP256EncryptedKey;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EciesNistP256EncryptedKeySpec extends BaseStructSpec {
	
	EciesNistP256EncryptedKey key1 = new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH]);
	EciesNistP256EncryptedKey key2 = new EciesNistP256EncryptedKey(2,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH]);
	
	
	def "Verify constructors and getters and setters"(){
		when:
		EciesNistP256EncryptedKey empty = new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256);
		then:
		empty.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		empty.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		expect:		
		key1.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		key1.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		key1.v.getX().intValue() == 1
		key1.c.length == SymmetricAlgorithm.aes_128_ccm.keyLength
		key1.t.length == EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH
		
		key2.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		key2.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		key2.v.getX().intValue() == 1
		key2.c.length == SymmetricAlgorithm.aes_128_ccm.keyLength
		key2.t.length == EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH

	}
	

	def "Verify that constructor throws IllegalArgumentException for wrong version data"(){
		when:
		new EciesNistP256EncryptedKey(2,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH]);
		then:
		thrown IllegalArgumentException
		when:
		new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH]);
		then:
		thrown IllegalArgumentException
	}

	def "Verify serialization of EciesNistP256EncryptedKey"(){
		when: 
		String result = serializeToHex(key1);
		then:
		
		result.length() /2 == 69;
		result.substring(0,2) == "00" // v.EccPointType is correct
		result.substring(2,66) == "0000000000000000000000000000000000000000000000000000000000000001" // v.X Value have been serialized.
		result.substring(66,98) == "00000000000000000000000000000000" // the c key (16 bytes)
		result.substring(98) == "0000000000000000000000000000000000000000" // the t output tag (20 bytes)

		when:
		result = serializeToHex(key2);
		then:
		
		result.length() /2 == 65;
		result.substring(0,2) == "00" // v.EccPointType is correct
		result.substring(2,66) == "0000000000000000000000000000000000000000000000000000000000000001" // v.X Value have been serialized.
		result.substring(66,98) == "00000000000000000000000000000000" // the c key (16 bytes)
		result.substring(98) == "00000000000000000000000000000000" // the t output tag (16 bytes)
	}
	
	def "Verify deserialization of EciesNistP256EncryptedKey"(){
		when:                                                                                                                                                         // ecc point type // x key value                                                 // the c key (16 bytes)                 // the t output tag (20 bytes)
		EciesNistP256EncryptedKey result = deserializeFromHex(new EciesNistP256EncryptedKey(1, PublicKeyAlgorithm.ecies_nistp256), "00" + "0000000000000000000000000000000000000000000000000000000000000001" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		result.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		result.v.getX().intValue() == 1
		result.c.length == SymmetricAlgorithm.aes_128_ccm.keyLength
		result.t.length == EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH
		
		when:                                                                                             // ecc point type // x key value               // the c key (16 bytes)                 // the t output tag (16 bytes)
		result = deserializeFromHex(new EciesNistP256EncryptedKey(2, PublicKeyAlgorithm.ecies_nistp256), "00" + "0000000000000000000000000000000000000000000000000000000000000001" + "00000000000000000000000000000000" + "00000000000000000000000000000000");
		then:
		result.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		result.symmetricAlgorithm == SymmetricAlgorithm.aes_128_ccm
		result.v.getX().intValue() == 1
		result.c.length == SymmetricAlgorithm.aes_128_ccm.keyLength
		result.t.length == EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH

	}
	

	def "Verify hashCode and equals"(){
		setup:
		def o1  = new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH]);
		def o2  = new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], Hex.decode("0011223344556677889900112233445566778899"));
		def o3  = new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)),  Hex.decode("00112233445566778899112233445566"), new byte[EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH]);
		def o4  = new EciesNistP256EncryptedKey(1,PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(2)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH]);

		expect:
		key1 == o1
		key1 != o2
		key1 != o3
		key1 != o4

		key1.hashCode() == o1.hashCode()
		key1.hashCode() != o2.hashCode()
		key1.hashCode() != o3.hashCode()
		key1.hashCode() != o4.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		 key1.toString() == "EciesNistP256EncryptedKey [publicKeyAlgorithm=ecies_nistp256, symmetricAlgorithm=aes_128_ccm, v=[eccPointType=x_coordinate_only, x=1], c=00000000000000000000000000000000, t=0000000000000000000000000000000000000000]"
	}

}
