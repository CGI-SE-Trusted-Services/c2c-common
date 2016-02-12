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
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.msg.EciesNistP256EncryptedKey;
import org.certificateservices.custom.c2x.its.datastructs.msg.RecipientInfo;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class RecipientInfoSpec extends BaseStructSpec {
	
	EciesNistP256EncryptedKey key1 = new EciesNistP256EncryptedKey(PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH]);
	RecipientInfo ri1 = new RecipientInfo(new HashedId8("123456789".getBytes()), key1);
	
	def "Verify constructors and getters and setters"(){
		expect:		
		ri1.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		ri1.certId != null
		ri1.pkEncryption != null
	}
	

	def "Verify serialization of RecipientInfo"(){
		when: 
		String result = serializeToHex(ri1);
		then:
		result.length() /2 == 78;
		result.substring(0,16) == "3233343536373839" // cert id
		result.substring(16,18) == "01" // public key algorithm
		result.substring(18,20) == "00" // v.EccPointType is correct
		result.substring(20,84) == "0000000000000000000000000000000000000000000000000000000000000001" // v.X Value have been serialized.
		result.substring(84,116) == "00000000000000000000000000000000" // the c key (16 bytes)
		result.substring(116) == "0000000000000000000000000000000000000000" // the t output tag (20 bytes)

	}
	
	def "Verify deserialization of EciesNistP256EncryptedKey"(){
		when:                                                        // cert id  // pk alg  // ecc point type // x key value                                                 // the c key (16 bytes)                 // the t output tag (20 bytes)
		RecipientInfo ri1 = deserializeFromHex(new RecipientInfo(), "3233343536373839" + "01" + "00" + "0000000000000000000000000000000000000000000000000000000000000001" + "00000000000000000000000000000000" + "0000000000000000000000000000000000000000");
		then:
		ri1.publicKeyAlgorithm == PublicKeyAlgorithm.ecies_nistp256
		ri1.certId != null
		ri1.pkEncryption != null

	}
	

	def "Verify hashCode and equals"(){
		setup:
		def o1  = new RecipientInfo(new HashedId8("123456789".getBytes()), key1);
		def o2  = new RecipientInfo(new HashedId8("133456789".getBytes()), key1);
		def o3  = new RecipientInfo(new HashedId8("123456789".getBytes()), new EciesNistP256EncryptedKey(PublicKeyAlgorithm.ecies_nistp256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(2)), new byte[SymmetricAlgorithm.aes_128_ccm.keyLength], new byte[EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH]));
		
		expect:
		ri1 == o1
		ri1 != o2
		ri1 != o3

		ri1.hashCode() == o1.hashCode()
		ri1.hashCode() != o2.hashCode()
		ri1.hashCode() != o3.hashCode()
	}
	
	def "Verify toString"(){
		expect:
		 ri1.toString() == "RecipientInfo [certId=HashedId8 [hashedId=[50, 51, 52, 53, 54, 55, 56, 57]], publicKeyAlgorithm=ecies_nistp256, pkEncryption=EciesNistP256EncryptedKey [publicKeyAlgorithm=ecies_nistp256, symmetricAlgorithm=aes_128_ccm, v=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, x=1, eccPointType=x_coordinate_only], c=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], t=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]]"
	}

}
