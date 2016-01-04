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
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerField;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerFieldType;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class TrailerFieldSpec extends BaseStructSpec {
	
	byte[] testSignature = Hex.decode("1122334455667788990011223344556677889900112233445566778899001122");
	Signature s =new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.compressed_lsb_y_0, new BigInteger(1)), testSignature))
	TrailerField tf1 = new TrailerField(s);
	
	def "Verify constructors and getters and setters"(){
		expect:		
		tf1.trailerFieldType == TrailerFieldType.signature
		tf1.signature != null
	}
	

	def "Verify serialization of RecipientInfo"(){
		when: 
		String result = serializeToHex(tf1);
		then:
		result.length() /2 == 67;
		result.substring(0,2) == "01" // type
		result.substring(2) == "00" + "02" + "0000000000000000000000000000000000000000000000000000000000000001" + "1122334455667788990011223344556677889900112233445566778899001122"// Signature

	}
	
	def "Verify deserialization of EciesNistP256EncryptedKey"(){
		when:                                                        //type     // Signature
		TrailerField tf1 = deserializeFromHex(new TrailerField(), "01" + "00" + "02" + "0000000000000000000000000000000000000000000000000000000000000001" + "1122334455667788990011223344556677889900112233445566778899001122");
		then:
		tf1.trailerFieldType == TrailerFieldType.signature
		tf1.signature != null

	}
	


	
	def "Verify toString"(){
		expect:
		 tf1.toString() == "TrailerField [trailerFieldType=signature, signature=Signature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, ecdsaSignature=EcdsaSignature [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, r=EccPoint [publicKeyAlgorithm=ecdsa_nistp256_with_sha256, compressedEncoding=null, eccPointType=compressed_lsb_y_0], signatureValue=[17, 34, 51, 68, 85, 102, 119, -120, -103, 0, 17, 34, 51, 68, 85, 102, 119, -120, -103, 0, 17, 34, 51, 68, 85, 102, 119, -120, -103, 0, 17, 34]]]]"
	}

}
